/*  Copyright (C) 2026 Kamila Szewczyk

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <lzma.h>

#include "block.h"
#include "schema.h"

#define FER_X_COL(e, n, t) { n, t },
static const fer_col_t conn_cols[] = { FER_CONN_COLUMNS(FER_X_COL) };
static const fer_col_t req_cols[] = { FER_REQ_COLUMNS(FER_X_COL) };

const fer_table_t fer_tables[3] = {
  { 0, NULL, NULL, 0 },
  { FER_TABLE_CONN, "conn", conn_cols, FER_CONN_NCOLS },
  { FER_TABLE_REQ, "req", req_cols, FER_REQ_NCOLS },
};

typedef struct { u8 * p;  sz len, cap;  int oom; } buf;

static int reserve(buf * b, sz n) {
  sz cap;  u8 * p;
  if (b->oom) return -1;
  if (b->len + n <= b->cap) return 0;
  for (cap = b->cap ? b->cap : KiB(64); cap < b->len + n; cap *= 2);
  if (!(p = realloc(b->p, cap))) { b->oom = 1;  return -1; }
  b->p = p;  b->cap = cap;
  return 0;
}

static void put(buf * b, const void * p, sz n) {
  if (!n || reserve(b, n)) return;
  memcpy(b->p + b->len, p, n);  b->len += n;
}

static void put8(buf * b, u8 v) { put(b, &v, 1); }

static sz vlen(u64 v) { sz n = 1;  while (v >= 0x80) v >>= 7, n++;  return n; }

static void putv(buf * b, u64 v) {
  u8 t[10];  sz n = 0;
  while (v >= 0x80) t[n++] = (u8) (v | 0x80), v >>= 7;
  t[n++] = (u8) v;
  put(b, t, n);
}

static void puts_(buf * b, const void * p, sz n) { putv(b, n);  put(b, p, n); }

static u64 zigzag(i64 v) { return (u64) v << 1 ^ (u64) (v >> 63); }

static void seterr(char * err, sz n, const char * fmt, ...) {
  va_list ap;
  if (!err || !n) return;
  va_start(ap, fmt);  vsnprintf(err, n, fmt, ap);  va_end(ap);
}

static i64 fnum(const u8 * row, u32 off) { i64 v;  memcpy(&v, row + off + 1, 8);  return v; }

static const u8 * fbytes(const u8 * row, u32 off, u32 * len) {
  memcpy(len, row + off + 1, 4);
  return row + off + 5;
}

typedef struct { const u8 * p;  u32 len, code; } slot;

static u64 fnv(const u8 * p, sz n) {
  u64 h = 1469598103934665603ULL;  sz i;
  Fi(n, h ^= p[i];  h *= 1099511628211ULL);
  return h;
}
static int encode_column(buf * out, const fer_col_t * col, unsigned ci, const u8 * const * rows,
                         const u32 * idx, unsigned ncols, sz nrows, i64 * ts_min, i64 * ts_max) {
  sz r, k, np = 0, rawsz = 0, dictsz = 0, cap = 16, nd = 0;
  u8 enc = 0;  i64 prev = 0, v;  u32 off, len, * codes;  u64 h;
  slot * slots, ** order;  const u8 * p;
#define OFF(r) idx[(r) * ncols + ci]
  for (r = 0; r < nrows; r++) np += OFF(r) != 0;
  if (!np) return -1;
  if (np < nrows) {
    sz nb = (nrows + 7) / 8;
    enc |= 0x80;
    if (reserve(out, nb)) return 0;
    memset(out->p + out->len, 0, nb);
    for (r = 0; r < nrows; r++) if (OFF(r)) out->p[out->len + (r >> 3)] |= (u8) (1u << (r & 7));
    out->len += nb;
  }
  if (col->type != FER_T_B) {
    for (r = 0; r < nrows; r++) {
      if (!(off = OFF(r))) continue;
      v = fnum(rows[r], off);
      if (!ci) { *ts_min = MIN(*ts_min, v);  *ts_max = MAX(*ts_max, v); }
      if (col->type == FER_T_S) putv(out, zigzag(v));
      else if (col->type == FER_T_TS) putv(out, zigzag((i64) ((u64) v - (u64) prev))), prev = v;
      else putv(out, (u64) v);
    }
    return enc;
  }
  while (cap < np * 2) cap *= 2;
  slots = calloc(cap, sizeof *slots);
  codes = malloc(np * sizeof *codes);
  order = malloc(np * sizeof *order);
  if (!slots || !codes || !order) {
    free(slots);  free(codes);  free(order);  out->oom = 1;
    return 0;
  }
  for (r = k = 0; r < nrows; r++) {
    if (!(off = OFF(r))) continue;
    p = fbytes(rows[r], off, &len);
    rawsz += vlen(len) + len;
    for (h = fnv(p, len) & (cap - 1);; h = (h + 1) & (cap - 1)) {
      slot * s = &slots[h];
      if (!s->code) {
        s->p = p;  s->len = len;  s->code = (u32) ++nd;  order[nd - 1] = s;
        dictsz += vlen(len) + len;
        break;
      }
      if (s->len == len && !memcmp(s->p, p, len)) break;
    }
    codes[k++] = slots[h].code - 1;
  }
  dictsz += vlen(nd);
  for (k = 0; k < np; k++) dictsz += vlen(codes[k]);
  if (dictsz < rawsz) {
    enc |= 1;
    putv(out, nd);
    for (k = 0; k < nd; k++) puts_(out, order[k]->p, order[k]->len);
    for (k = 0; k < np; k++) putv(out, codes[k]);
  } else {
    for (r = 0; r < nrows; r++)
      if ((off = OFF(r))) { p = fbytes(rows[r], off, &len);  puts_(out, p, len); }
  }
#undef OFF
  free(slots);  free(codes);  free(order);
  return enc;
}

static int index_row(const fer_table_t * t, const u8 * row, u32 n, u32 * idx) {
  u16 nf, f;  u32 off = FER_ROW_HDR, len;  u8 col;
  memcpy(&nf, row + 6, 2);
  for (f = 0; f < nf; f++) {
    if (off + 1 > n || (col = row[off]) >= t->ncols) return -1;
    if (t->cols[col].type == FER_T_B) {
      if (off + 5 > n) return -1;
      memcpy(&len, row + off + 1, 4);
      if (len > n - off - 5) return -1;
      idx[col] = off;  off += 5 + len;
    } else {
      if (off + 9 > n) return -1;
      idx[col] = off;  off += 9;
    }
  }
  return 0;
}

static u32 row_at(const u8 * rows, sz len, sz pos) {
  u32 rl;
  if (pos + FER_ROW_HDR > len) return 0;
  memcpy(&rl, rows + pos, 4);
  return rl < FER_ROW_HDR || rl > len - pos ? 0 : rl;
}

static void wr16le(u8 * p, u16 v) { p[0] = (u8) v;  p[1] = (u8) (v >> 8); }

static int encode_block(buf * file, const fer_table_t * t, const u8 * rows, sz len,
                        const fer_kv_t * meta, unsigned nmeta, u32 preset, char * err, sz errlen) {
  sz pos, nrows = 0, r, i, start, xz_pos = 0, xz_cap, at;
  u32 rl, * idx, ncols = 0;
  int enc;  i64 ts_min = INT64_MAX, ts_max = INT64_MIN;
  const u8 ** refs;  buf raw = { 0 }, sect = { 0 }, dir = { 0 };
  lzma_ret lr;  u8 hdr[52];
  for (pos = 0; (rl = row_at(rows, len, pos)); pos += rl) nrows += rows[pos + 4] == t->id;
  if (!nrows) return 0;
  refs = malloc(nrows * sizeof *refs);
  idx = calloc(nrows * t->ncols, sizeof *idx);
  if (!refs || !idx) {
    free(refs);  free(idx);
    seterr(err, errlen, "out of memory indexing %zu rows", nrows);
    return -1;
  }
  for (pos = r = 0; r < nrows && (rl = row_at(rows, len, pos)); pos += rl) {
    if (rows[pos + 4] != t->id) continue;
    if (index_row(t, rows + pos, rl, idx + r * t->ncols)) {
      memset(idx + r * t->ncols, 0, t->ncols * sizeof *idx);
      continue;
    }
    refs[r++] = rows + pos;
  }
  nrows = r;
  for (i = 0; i < t->ncols && nrows; i++) {
    start = raw.len;
    enc = encode_column(&raw, &t->cols[i], (unsigned) i, refs, idx, t->ncols, nrows, &ts_min, &ts_max);
    if (enc < 0) continue;
    puts_(&dir, t->cols[i].name, strlen(t->cols[i].name));
    put8(&dir, t->cols[i].type);  put8(&dir, (u8) enc);
    putv(&dir, start);  putv(&dir, raw.len - start);
    ncols++;
  }
  free(refs);  free(idx);
  if (!nrows) { free(raw.p);  free(dir.p);  return 0; }
  if (ts_min == INT64_MAX) ts_min = ts_max = 0;
  putv(&sect, nmeta);
  Fi(nmeta, puts_(&sect, meta[i].key, strlen(meta[i].key));
            puts_(&sect, meta[i].value, strlen(meta[i].value)));
  put(&sect, dir.p, dir.len);  free(dir.p);
  if (raw.oom || sect.oom) {
    free(raw.p);  free(sect.p);
    seterr(err, errlen, "out of memory encoding %s block", t->name);
    return -1;
  }
  memcpy(hdr, "FER1", 4);
  wr16le(hdr + 4, FER_FORMAT_VERSION);  wr16le(hdr + 6, t->id);
  wr32le(hdr + 8, (u32) nrows);  wr32le(hdr + 12, ncols);  wr32le(hdr + 16, (u32) sect.len);
  wr64le(hdr + 20, raw.len);
  wr64le(hdr + 36, (u64) ts_min);  wr64le(hdr + 44, (u64) ts_max);
  xz_cap = lzma_stream_buffer_bound(raw.len);
  at = file->len;
  if (reserve(file, sizeof hdr + sect.len + 4 + xz_cap)) {
    free(raw.p);  free(sect.p);
    seterr(err, errlen, "out of memory for %zu byte block", xz_cap);
    return -1;
  }
  file->len += sizeof hdr;
  put(file, sect.p, sect.len);
  file->len += 4;
  lr = lzma_easy_buffer_encode(preset, LZMA_CHECK_CRC64, NULL, raw.p, raw.len,
                               file->p + file->len, &xz_pos, xz_cap);
  free(raw.p);
  if (lr != LZMA_OK) {
    free(sect.p);  file->len = at;
    seterr(err, errlen, "lzma_easy_buffer_encode failed: %d", (int) lr);
    return -1;
  }
  /*  The CRC covers the header with xz_len filled in.  */
  wr64le(hdr + 28, xz_pos);
  memcpy(file->p + at, hdr, sizeof hdr);
  wr32le(file->p + at + sizeof hdr + sect.len, lzma_crc32(file->p + at, sizeof hdr + sect.len, 0));
  file->len += xz_pos;
  free(sect.p);
  return 0;
}

int fer_write_blocks(const char * dir, const u8 * rows, sz len, const fer_kv_t * meta, unsigned nmeta,
                     u32 preset, i64 now_us, char * err, sz errlen) {
  char name[32], path[4096];  buf f = { 0 };
  unsigned t;  int fd;  sz done;  ssize_t n;
  time_t now = (time_t) (now_us / 1000000);  struct tm tm;
  for (t = 1; t < 3; t++)
    if (encode_block(&f, &fer_tables[t], rows, len, meta, nmeta, preset, err, errlen)) {
      free(f.p);
      return -1;
    }
  if (!f.len) { free(f.p);  return 0; }
  gmtime_r(&now, &tm);
  strftime(name, sizeof name, "%Y-%m-%d.fer", &tm);
  if ((sz) snprintf(path, sizeof path, "%s/%s", dir, name) >= sizeof path) {
    free(f.p);  seterr(err, errlen, "path too long");
    return -1;
  }
  if ((fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640)) == -1) {
    seterr(err, errlen, "open(\"%s\") failed: %s", path, strerror(errno));
    free(f.p);
    return -1;
  }
  for (done = 0; done < f.len; done += (sz) n) {
    if ((n = write(fd, f.p + done, f.len - done)) > 0) continue;
    if (n < 0 && errno == EINTR) { n = 0;  continue; }
    seterr(err, errlen, "write(\"%s\") failed after %zu of %zu bytes: %s", path, done, f.len,
           n < 0 ? strerror(errno) : "short write");
    close(fd);  free(f.p);
    return -1;
  }
  (void) fdatasync(fd);
  close(fd);  free(f.p);
  return 0;
}

int fer_retention_sweep(const char * dir, int days, i64 now_us) {
  DIR * d;  struct dirent * de;  struct tm tm;
  time_t now = (time_t) (now_us / 1000000), cutoff, ft;
  int y, m, dd, removed = 0, nc;  char path[4096];
  if (days < 0) return 0;
  if (!(d = opendir(dir))) return -1;
  cutoff = now - now % 86400 - (time_t) days * 86400;
  while ((de = readdir(d))) {
    nc = 0;
    if (strlen(de->d_name) != 14 || sscanf(de->d_name, "%4d-%2d-%2d.fer%n", &y, &m, &dd, &nc) != 3 ||
        nc != 14)
      continue;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = y - 1900;  tm.tm_mon = m - 1;  tm.tm_mday = dd;
    if ((ft = timegm(&tm)) == (time_t) -1 || ft >= cutoff) continue;
    if ((sz) snprintf(path, sizeof path, "%s/%s", dir, de->d_name) < sizeof path && !unlink(path))
      removed++;
  }
  closedir(d);
  return removed;
}
