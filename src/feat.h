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

/*  Features of a connection: TLS ClientHello fingerprints, the saved SYN,
    query scrubbing, keyed hashing and intel.bin lookups.  Needs libcrypto.  */

#ifndef FER_FEAT_H
#define FER_FEAT_H

#include "common.h"

typedef struct {
  u16 legacy_version;
  const u8 * ciphers;  sz ciphers_len;  /*  u16be list.  */
  const u8 * exts;  sz exts_len;        /*  (u16 type, u16 len, data)*, in wire order.  */
} fer_hello_in_t;

typedef struct {
  char * sni, * alpn;
  u8 * versions;  sz versions_len;
  u8 * groups;  sz groups_len;
  u8 * sigalgs;  sz sigalgs_len;
  u8 * keyshare;  sz keyshare_len;
  unsigned grease;
  char ja4[48];  char * ja4_r;  char * ja3;  char ja3_hash[33];
  void * mem;
} fer_hello_t;

int fer_hello_parse(const fer_hello_in_t * in, fer_hello_t * out);
void fer_hello_free(fer_hello_t * h);

typedef struct {
  unsigned af, ttl, df, ipid, tos, flowlabel, iplen, ipopt_len, win, flags;
  int mss, wscale;
  u8 opts[40];  unsigned nopts;
  int has_ts;  u32 tsval, tsecr;
  unsigned payload_len, urgptr;  u32 seq;  unsigned ack_nonzero;
  char ja4t[200];
} fer_syn_t;

int fer_syn_parse(const u8 * p, sz len, fer_syn_t * s);

enum { FER_H2_PREFACE, FER_H2_HEAD, FER_H2_BODY, FER_H2_OFF };
#define FER_H2_NTYPES 11                 /*  DATA .. CONTINUATION, then other.  */
#define FER_H2_HBMAX KiB(16)             /*  Of the first header block.  */

typedef struct {
  u8 state, is_h2;
  u8 fh[9], fhlen;                       /*  Frame header being read.  */
  u8 type, flags;  u32 len, sid, got;    /*  Current frame.  */
  u8 pb[256];                            /*  Its first bytes, for small frames.  */
  u8 * hb;  sz hblen;                    /*  First header block, malloc'd.  */
  u8 collect, in_block, headers_seen, block_done, settings_seen, wu_seen, hprio_seen, goaway_seen;
  u8 eof;                                /*  Client closed: 1 between frames, 2 inside one.  */
  char settings[200], prio[256], pseudo[12], hprio[32];
  u32 wu, goaway_code, max_sid;
  u32 frames[FER_H2_NTYPES];
  u64 bytes;
} fer_h2_t;

int fer_h2_feed(fer_h2_t * h, const u8 * p, sz n);
void fer_h2_eof(fer_h2_t * h);
void fer_h2_finish(fer_h2_t * h);
void fer_h2_fp(const fer_h2_t * h, char * out, sz cap);

sz fer_scrub(const u8 * src, sz len, u8 * dst, sz dstcap, int whole_is_query);

void fer_khash(const u8 * key, sz keylen, const u8 * data, sz len, u8 out[8]);

typedef struct {
  void * map;  sz size;
  u32 version, n4, n6, nasn;
  const u8 * t4, * t6, * tasn;
} fer_intel_t;

int fer_intel_open(fer_intel_t * in, const char * path, char * err, sz errlen);
void fer_intel_close(fer_intel_t * in);

u64 fer_intel_ip(const fer_intel_t * in, const u8 * addr, sz alen, unsigned * score);
u64 fer_intel_asn(const fer_intel_t * in, u32 asn);

#endif
