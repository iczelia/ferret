# ferret

An nginx module that records per-connection and per-request client features
(SYN, TCP_INFO, TLS ClientHello with JA3/JA4, HTTP/2 preface and frame
counts, headers, timings, geo/ASN/threat intel) into columnar, xz-compressed
`.fer` files.

Built for Debian 13's nginx 1.26 with HTTP/1.1, HTTP/2 (over TLS and
cleartext) and TLS; HTTP/3 is not fingerprinted.

## Building and testing

The module is built against Debian's `nginx-dev` tree so that it loads into
the distro binary; rebuild after each nginx upgrade.

    podman build -t ferret-build .
    podman run --rm -v $PWD:/src:Z ferret-build make
    podman run --rm --cap-add NET_RAW,NET_ADMIN -v $PWD:/src:Z ferret-build make test

`make test` also runs everything under ASan/UBSan.  `NET_RAW` is for tcpdump,
`NET_ADMIN` for aliasing test addresses onto `lo`.  The ASN check runs only if
`cache/dbip-asn-lite.mmdb` exists (`tools/ferret-geo --dir cache --only asn`).

## Installing

    scp -r out contrib tools server:ferret/
    ssh server 'cd ferret && sudo contrib/install.sh'

Then include `contrib/ferret.conf` in `http{}` and reload nginx.

## Directives

Context is `http` unless noted.

    ferret_path DIR                   enable; writes DIR/YYYY-MM-DD.fer (UTC)
    ferret on|off                     http/server/location; off drops req rows (on)
    ferret_shm NAME SIZE              staging zone, two buffers (ferret 64m)
    ferret_block_size SIZE            flush a buffer at this size, at most zone/3 (8m)
    ferret_flush_interval TIME        ... or when its oldest row is this old (10m)
    ferret_xz_preset 0-9[e]           (6)
    ferret_thread_pool NAME|off       where xz and write run (default)
    ferret_retention DAYS|-1|off      delete older day files after each flush (-1)
    ferret_geo_db FILE                DB-IP City mmdb
    ferret_asn_db FILE                DB-IP ASN mmdb
    ferret_intel_db FILE              intel.bin from ferret-intel
    ferret_hash_key FILE              16-4096 byte key for HMAC of cookies/credentials
    ferret_capture_header NAME...     extra headers, stored in h_extra
    ferret_save_syn on|off            TCP_SAVE_SYN on listeners (on)
    ferret_rdns on|off                PTR plus forward-confirm at accept; needs resolver (off)
    ferret_rdns_timeout TIME          (1s)
    ferret_trap PREFIX...             http/server/location; sets trap_hit
    ferret_tag VALUE                  http/server/location; complex value stored in tag

## Reading

    ferread.py /var/log/ferret/*.fer --table req --join --since 2026-11-08 > req.jsonl
    ferread.py FILES --table conn --format parquet --out conn.parquet
    ferread.py FILES --verify

## License

AGPLv3, see COPYING.
