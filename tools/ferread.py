#!/usr/bin/env python3

import argparse
import csv
import datetime as dt
import ipaddress
import json
import lzma
import struct
import sys
import zlib

MAGIC = b"FER1"
HDR = struct.Struct("<4sHHIIIQQqq")      # 52 bytes
TABLES = {1: "conn", 2: "req"}
T_U, T_S, T_TS, T_B = 1, 2, 3, 4

ADDR_COLS = {"client_addr", "server_addr"}
U16_LIST_COLS = {"hello_ciphers", "tls_versions_offered", "groups_offered",
                 "sigalgs_offered", "keyshare_groups"}
HEX_COLS = {"syn_raw", "hello_exts", "hello_compression", "auth_hash",
            "cookie_hashes", "syn_opts"}


class Corrupt(Exception):
    pass


def varint(buf, pos):
    shift = 0
    v = 0
    while True:
        if pos >= len(buf):
            raise Corrupt("varint past end")
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, pos
        shift += 7
        if shift > 70:
            raise Corrupt("varint too long")


def unzigzag(v):
    return (v >> 1) ^ -(v & 1)


def rstr(buf, pos):
    n, pos = varint(buf, pos)
    if pos + n > len(buf):
        raise Corrupt("string past end")
    return bytes(buf[pos:pos + n]), pos + n


def decode_column(data, ctype, enc, nrows):
    pos = 0
    if enc & 0x80:
        nb = (nrows + 7) // 8
        bm = data[:nb]
        pos = nb
        present = [(bm[i >> 3] >> (i & 7)) & 1 for i in range(nrows)]
    else:
        present = [1] * nrows
    npresent = sum(present)
    vals = []
    if ctype != T_B:
        prev = 0
        for _ in range(npresent):
            v, pos = varint(data, pos)
            if ctype == T_S:
                v = unzigzag(v)
            elif ctype == T_TS:
                v = prev + unzigzag(v)
                prev = v
            elif v >= 1 << 63:          # U column stored from a negative i64
                v -= 1 << 64
            vals.append(v)
    elif enc & 0x0F == 1:
        nd, pos = varint(data, pos)
        d = []
        for _ in range(nd):
            s, pos = rstr(data, pos)
            d.append(s)
        for _ in range(npresent):
            c, pos = varint(data, pos)
            if c >= nd:
                raise Corrupt("dict code out of range")
            vals.append(d[c])
    else:
        for _ in range(npresent):
            s, pos = rstr(data, pos)
            vals.append(s)
    it = iter(vals)
    return [next(it) if p else None for p in present]


def read_blocks(path, errors=None):
    """Yield (header dict, meta dict, {col: [values]}) for each valid block."""
    with open(path, "rb") as f:
        buf = f.read()
    pos = 0
    while pos < len(buf):
        if buf[pos:pos + 4] != MAGIC:
            nxt = buf.find(MAGIC, pos + 1)
            if errors is not None:
                errors.append(f"{path}@{pos}: garbage, skipping "
                              f"{(nxt if nxt >= 0 else len(buf)) - pos} bytes")
            if nxt < 0:
                return
            pos = nxt
            continue
        try:
            blk, end = parse_block(buf, pos)
        except Corrupt as e:
            if errors is not None:
                errors.append(f"{path}@{pos}: {e}")
            nxt = buf.find(MAGIC, pos + 1)
            if nxt < 0:
                return
            pos = nxt
            continue
        yield blk
        pos = end


def parse_block(buf, pos):
    if pos + HDR.size > len(buf):
        raise Corrupt("truncated header")
    (magic, ver, table, nrows, ncols, sect_len, raw_len, xz_len,
     ts_min, ts_max) = HDR.unpack_from(buf, pos)
    if ver != 1:
        raise Corrupt(f"unknown version {ver}")
    s0 = pos + HDR.size
    if s0 + sect_len + 4 > len(buf):
        raise Corrupt("truncated section")
    crc_stored = struct.unpack_from("<I", buf, s0 + sect_len)[0]
    if zlib.crc32(buf[pos:s0 + sect_len]) != crc_stored:
        raise Corrupt("header CRC mismatch")
    x0 = s0 + sect_len + 4
    if x0 + xz_len > len(buf):
        raise Corrupt("truncated xz payload")

    sect = buf[s0:s0 + sect_len]
    p = 0
    nmeta, p = varint(sect, p)
    meta = {}
    for _ in range(nmeta):
        k, p = rstr(sect, p)
        v, p = rstr(sect, p)
        meta[k.decode()] = v.decode(errors="replace")
    cols = []
    for _ in range(ncols):
        name, p = rstr(sect, p)
        ctype = sect[p]
        enc = sect[p + 1]
        p += 2
        off, p = varint(sect, p)
        ln, p = varint(sect, p)
        cols.append((name.decode(), ctype, enc, off, ln))

    try:
        raw = lzma.decompress(buf[x0:x0 + xz_len], format=lzma.FORMAT_XZ)
    except lzma.LZMAError as e:
        raise Corrupt(f"xz: {e}")
    if len(raw) != raw_len:
        raise Corrupt("raw length mismatch")

    data = {}
    types = {}
    for name, ctype, enc, off, ln in cols:
        if off + ln > raw_len:
            raise Corrupt(f"column {name} out of range")
        data[name] = decode_column(raw[off:off + ln], ctype, enc, nrows)
        types[name] = ctype
    hdr = dict(table=TABLES.get(table, str(table)), nrows=nrows, ncols=ncols,
               raw_len=raw_len, xz_len=xz_len, ts_min=ts_min, ts_max=ts_max,
               types=types)
    return (hdr, meta, data), x0 + xz_len


def fmt_value(name, v):
    if v is None or not isinstance(v, bytes):
        return v
    if name in ADDR_COLS:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v.hex()
    if name in U16_LIST_COLS:
        return [int.from_bytes(v[i:i + 2], "big") for i in range(0, len(v) - 1, 2)]
    if name in HEX_COLS:
        return v.hex()
    try:
        s = v.decode("utf-8")
    except UnicodeDecodeError:
        return "hex:" + v.hex()
    if any(ord(c) < 32 and c not in "\n\t" for c in s):
        return "hex:" + v.hex()
    return s


def rows_of(blk):
    hdr, meta, data = blk
    names = list(data)
    for i in range(hdr["nrows"]):
        yield {n: fmt_value(n, data[n][i]) for n in names if data[n][i] is not None}


def parse_time(s):
    if s is None:
        return None
    if s.isdigit():
        return int(s)
    t = dt.datetime.fromisoformat(s)
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return int(t.timestamp() * 1_000_000)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--table", choices=["conn", "req"], default="req")
    ap.add_argument("--format", choices=["jsonl", "csv", "parquet"], default="jsonl")
    ap.add_argument("--join", action="store_true",
                    help="with --table req: add conn.* columns by conn_id")
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--out", help="output file (required for parquet)")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args(argv)

    errors = []
    since, until = parse_time(a.since), parse_time(a.until)

    if a.stats or a.verify:
        total = {}
        for f in a.files:
            for hdr, meta, data in read_blocks(f, errors):
                total[hdr["table"]] = total.get(hdr["table"], 0) + hdr["nrows"]
                if a.stats:
                    print(json.dumps({"file": f, **{k: v for k, v in hdr.items()
                                                    if k != "types"},
                                      "meta": meta}))
        for e in errors:
            print("ferread: " + e, file=sys.stderr)
        if a.stats:
            print(json.dumps({"totals": total}))
        return 1 if (a.verify and errors) else 0

    conns = {}
    if a.join and a.table == "req":
        for f in a.files:
            for blk in read_blocks(f, None):
                if blk[0]["table"] == "conn":
                    for r in rows_of(blk):
                        conns[r.get("conn_id")] = r

    out_rows = []
    for f in a.files:
        for blk in read_blocks(f, errors):
            if blk[0]["table"] != a.table:
                continue
            if since and blk[0]["ts_max"] < since:
                continue
            if until and blk[0]["ts_min"] > until:
                continue
            for r in rows_of(blk):
                ts = r.get("ts", 0)
                if (since and ts < since) or (until and ts > until):
                    continue
                if conns:
                    c = conns.get(r.get("conn_id"))
                    if c:
                        r.update({"conn." + k: v for k, v in c.items()})
                out_rows.append(r)

    for e in errors:
        print("ferread: " + e, file=sys.stderr)

    out = open(a.out, "w", newline="") if a.out and a.format != "parquet" else sys.stdout

    if a.format == "jsonl":
        for r in out_rows:
            out.write(json.dumps(r, ensure_ascii=False) + "\n")
    elif a.format == "csv":
        keys = list(dict.fromkeys(k for r in out_rows for k in r))
        w = csv.DictWriter(out, fieldnames=keys)
        w.writeheader()
        for r in out_rows:
            w.writerow({k: (json.dumps(v) if isinstance(v, list) else v)
                        for k, v in r.items()})
    else:
        if not a.out:
            ap.error("--format parquet needs --out")
        import pyarrow as pa
        import pyarrow.parquet as pq
        pq.write_table(pa.Table.from_pylist(out_rows), a.out)
    if out is not sys.stdout:
        out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
