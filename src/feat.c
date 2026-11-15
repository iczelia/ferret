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

#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "feat.h"

static const char hx[] = "0123456789abcdef";

static int is_grease(unsigned v) { return (v & 0x0f0f) == 0x0a0a && v >> 8 == (v & 0xff); }

static int cmp16(const void * a, const void * b) { return (int) *(const u16 *) a - (int) *(const u16 *) b; }

/*  The first `n' hex digits of the digest of s.  */
static void hexdigest(const EVP_MD * md, const char * s, sz len, char * out, sz n) {
  u8 d[EVP_MAX_MD_SIZE];  unsigned dl = 0;  sz i;
  EVP_Digest(s, len, d, &dl, md, NULL);
  for (i = 0; i < n && i / 2 < dl; i++) out[i] = hx[d[i / 2] >> (i & 1 ? 0 : 4) & 0xf];
  out[i] = 0;
}

/*  Append v[0, n) to p joined by sep, in hex for JA4 and in decimal for JA3.  */
static char * list(char * p, const u16 * v, sz n, int hex) {
  sz i;
  Fi(n, p += sprintf(p, hex ? (i ? ",%04x" : "%04x") : (i ? "-%u" : "%u"), v[i]));
  return p;
}

static const char * ja4_version(unsigned v) {
  switch (v) {
    case 0x0304: return "13";  case 0x0303: return "12";  case 0x0302: return "11";
    case 0x0301: return "10";  case 0x0300: return "s3";  case 0x0002: return "s2";
    case 0xfeff: return "d1";  case 0xfefd: return "d2";  case 0xfefc: return "d3";
    default: return "00";
  }
}

static u8 * dupb(const u8 * p, sz n) {
  u8 * d = malloc(n + 1);
  if (d) memcpy(d, p, n), d[n] = 0;
  return d;
}

/*  Copy a u16be list, noting GREASE in it.  */
static u8 * u16list(const u8 * p, sz n, sz * len, unsigned * grease, unsigned bit) {
  sz i;
  n &= ~(sz) 1;
  for (i = 0; i < n; i += 2) if (is_grease(rd16be(p + i))) *grease |= bit;
  *len = n;
  return dupb(p, n);
}

static sz nogrease(const u8 * p, sz n, u16 * out) {
  sz i, k = 0;
  for (i = 0; i + 1 < n; i += 2) if (!is_grease(rd16be(p + i))) out[k++] = rd16be(p + i);
  return k;
}

static sz inner(sz ll, sz pre, sz dl) { return ll + pre > dl ? dl - pre : ll; }

int fer_hello_parse(const fer_hello_in_t * in, fer_hello_t * h) {
  const u8 * e = in->exts, * end = in->exts + in->exts_len, * d, * alpn = NULL, * pf = NULL;
  sz dl, alpnlen = 0, pflen = 0, i, k, nciph, next = 0, nja4e = 0, nsig = 0, ncurves = 0, cap;
  unsigned type, maxver = 0, sni = 0;
  u16 * ciph, * exts, * ja4e, * sig = NULL, * curves = NULL;
  char * buf, * p, a[16], alpn2[3] = "00";
  memset(h, 0, sizeof *h);
  ciph = malloc((in->ciphers_len / 2 + 1) * sizeof *ciph);
  exts = malloc((in->exts_len / 4 + 1) * sizeof *exts);
  ja4e = malloc((in->exts_len / 4 + 1) * sizeof *ja4e);
  if (!ciph || !exts || !ja4e) { free(ciph);  free(exts);  free(ja4e);  return -1; }
  for (i = 0; i + 1 < in->ciphers_len; i += 2) if (is_grease(rd16be(in->ciphers + i))) h->grease |= 1;
  nciph = nogrease(in->ciphers, in->ciphers_len, ciph);
  while (e + 4 <= end) {
    type = rd16be(e);  dl = rd16be(e + 2);  d = e + 4;
    if (d + dl > end) break;
    e = d + dl;
    if (is_grease(type)) { h->grease |= 2;  continue; }
    exts[next++] = (u16) type;
    if (type != 0x0000 && type != 0x0010) ja4e[nja4e++] = (u16) type;
    switch (type) {
      case 0x0000:  /*  server_name  */
        sni = 1;
        if (dl >= 5 && !d[2] && 5 + (sz) rd16be(d + 3) <= dl && !h->sni) h->sni = (char *) dupb(d + 5, rd16be(d + 3));
        break;
      case 0x0010:  /*  ALPN  */
        if (dl >= 2 && !h->alpn) {
          sz ll = inner(rd16be(d), 2, dl), off = 2, pl;
          char * q;
          alpn = d + 2;  alpnlen = ll;
          if (!(q = h->alpn = malloc(ll + 1))) break;
          while (off < ll + 2) {
            pl = d[off++];
            if (off + pl > ll + 2) break;
            if (q != h->alpn) *q++ = ',';
            memcpy(q, d + off, pl);  q += pl;  off += pl;
          }
          *q = 0;
        }
        break;
      case 0x002b:  /*  supported_versions  */
        if (dl >= 1 && !h->versions) {
          h->versions = u16list(d + 1, inner(d[0], 1, dl), &h->versions_len, &h->grease, 8);
          for (k = 0; k + 1 < h->versions_len; k += 2) {
            unsigned v = rd16be(h->versions + k);
            if (!is_grease(v) && v > maxver) maxver = v;
          }
        }
        break;
      case 0x000a:  /*  supported_groups  */
        if (dl >= 2 && !h->groups) {
          sz ll = inner(rd16be(d), 2, dl);
          h->groups = u16list(d + 2, ll, &h->groups_len, &h->grease, 4);
          if ((curves = malloc((ll / 2 + 1) * sizeof *curves))) ncurves = nogrease(d + 2, ll, curves);
        }
        break;
      case 0x000b:  /*  ec_point_formats  */
        if (dl >= 1 && !pf) pflen = inner(d[0], 1, dl), pf = d + 1;
        break;
      case 0x000d:  /*  signature_algorithms  */
        if (dl >= 2 && !h->sigalgs) {
          sz ll = inner(rd16be(d), 2, dl);
          h->sigalgs = u16list(d + 2, ll, &h->sigalgs_len, &h->grease, 16);
          if ((sig = malloc((ll / 2 + 1) * sizeof *sig))) nsig = nogrease(d + 2, ll, sig);
        }
        break;
      case 0x0033:  /*  key_share: keep the groups, not the keys  */
        if (dl >= 2 && !h->keyshare) {
          sz ll = inner(rd16be(d), 2, dl), off = 2, n = 0;
          u8 * ks = malloc(ll + 1);
          if (!ks) break;
          for (; off + 4 <= ll + 2; off += 4 + rd16be(d + off + 2)) {
            unsigned g = rd16be(d + off);
            if (is_grease(g)) h->grease |= 32;
            ks[n++] = (u8) (g >> 8);  ks[n++] = (u8) g;
          }
          h->keyshare = ks;  h->keyshare_len = n;
        }
        break;
    }
  }
  if (!maxver) maxver = in->legacy_version;
  /*  JA4 takes the first and last character of the first ALPN value, in hex
      when they are not alphanumeric.  */
  if (alpn && alpnlen >= 1 && alpn[0] && (sz) alpn[0] + 1 <= alpnlen) {
    u8 f = alpn[1], l = alpn[alpn[0]];
    if (isalnum(f) && isalnum(l)) alpn2[0] = (char) f, alpn2[1] = (char) l;
    else alpn2[0] = hx[f >> 4], alpn2[1] = hx[l & 0xf];
  }
  snprintf(a, sizeof a, "t%s%c%02zu%02zu%s", ja4_version(maxver), sni ? 'd' : 'i', MIN(nciph, 99),
           MIN(next, 99), alpn2);
  qsort(ciph, nciph, sizeof *ciph, cmp16);
  qsort(ja4e, nja4e, sizeof *ja4e, cmp16);
  cap = 64 + 5 * (nciph + nja4e + nsig);
  h->ja4_r = malloc(cap);
  buf = malloc(cap);
  if (h->ja4_r && buf) {
    char hb[13] = "000000000000", hc[13] = "000000000000";
    p = list(buf, ciph, nciph, 1);
    if (nciph) hexdigest(EVP_sha256(), buf, (sz) (p - buf), hb, 12);
    p = list(buf, ja4e, nja4e, 1);
    if (nsig) *p++ = '_', p = list(p, sig, nsig, 1);
    if (nja4e) hexdigest(EVP_sha256(), buf, (sz) (p - buf), hc, 12);
    snprintf(h->ja4, sizeof h->ja4, "%s_%s_%s", a, hb, hc);
    p = h->ja4_r + sprintf(h->ja4_r, "%s_", a);
    p = list(p, ciph, nciph, 1);  *p++ = '_';
    p = list(p, ja4e, nja4e, 1);
    if (nsig) *p++ = '_', p = list(p, sig, nsig, 1);
    *p = 0;
  }
  free(buf);
  /*  JA3 keeps the ciphers in wire order.  */
  nciph = nogrease(in->ciphers, in->ciphers_len, ciph);
  if ((h->ja3 = malloc(64 + 6 * (nciph + next + ncurves) + 4 * pflen))) {
    p = h->ja3 + sprintf(h->ja3, "%u,", in->legacy_version);
    p = list(p, ciph, nciph, 0);  *p++ = ',';
    p = list(p, exts, next, 0);  *p++ = ',';
    p = list(p, curves, ncurves, 0);  *p++ = ',';
    Fi(pflen, p += sprintf(p, i ? "-%u" : "%u", pf[i]));
    *p = 0;
    hexdigest(EVP_md5(), h->ja3, (sz) (p - h->ja3), h->ja3_hash, 32);
  }
  free(ciph);  free(exts);  free(ja4e);  free(sig);  free(curves);
  return 0;
}

void fer_hello_free(fer_hello_t * h) {
  free(h->sni);  free(h->alpn);  free(h->versions);  free(h->groups);
  free(h->sigalgs);  free(h->keyshare);  free(h->ja4_r);  free(h->ja3);
  memset(h, 0, sizeof *h);
}

int fer_syn_parse(const u8 * p, sz len, fer_syn_t * s) {
  sz ihl, thl, off, total;  unsigned nh;  char * q;
  memset(s, 0, sizeof *s);
  s->mss = s->wscale = -1;
  if (len < 20) return -1;
  if (p[0] >> 4 == 4) {
    ihl = (sz) (p[0] & 0x0f) * 4;
    if (ihl < 20 || len < ihl + 20) return -1;
    s->af = 4;  s->tos = p[1];  s->iplen = rd16be(p + 2);  s->ipid = rd16be(p + 4);
    s->df = !!(p[6] & 0x40);  s->ttl = p[8];  s->ipopt_len = (unsigned) (ihl - 20);
    if (p[9] != 6) return -1;
  } else if (p[0] >> 4 == 6) {
    if (len < 40 + 20) return -1;
    s->af = 6;  s->tos = (p[0] & 0x0f) << 4 | p[1] >> 4;
    s->flowlabel = (unsigned) (p[1] & 0x0f) << 16 | rd16be(p + 2);
    s->iplen = rd16be(p + 4) + 40u;  s->ttl = p[7];
    /*  Skip hop-by-hop, routing and destination options headers.  */
    for (nh = p[6], ihl = 40; nh == 0 || nh == 43 || nh == 60; ihl += ((sz) p[ihl + 1] + 1) * 8) {
      if (len < ihl + 8) return -1;
      nh = p[ihl];
    }
    if (nh != 6 || len < ihl + 20) return -1;
    s->ipopt_len = (unsigned) (ihl - 40);
  } else return -1;
  total = s->iplen;
  p += ihl;  len -= ihl;
  s->seq = rd32be(p + 4);  s->ack_nonzero = !!rd32be(p + 8);
  thl = (sz) (p[12] >> 4) * 4;
  s->flags = (unsigned) (p[12] & 1) << 8 | p[13];
  s->win = rd16be(p + 14);  s->urgptr = rd16be(p + 18);
  if (thl < 20 || thl > len) thl = len < 20 ? 20 : MIN(thl, len);
  if (total >= ihl + thl) s->payload_len = (unsigned) (total - ihl - thl);
  for (off = 20; off < thl;) {
    unsigned kind = p[off], olen;
    if (s->nopts < sizeof s->opts) s->opts[s->nopts++] = (u8) kind;
    if (!kind) break;
    if (kind == 1) { off++;  continue; }
    if (off + 1 >= thl) break;
    olen = p[off + 1];
    if (olen < 2 || off + olen > thl) break;
    if (kind == 2 && olen == 4) s->mss = rd16be(p + off + 2);
    else if (kind == 3 && olen == 3) s->wscale = p[off + 2];
    else if (kind == 8 && olen == 10) s->has_ts = 1, s->tsval = rd32be(p + off + 2), s->tsecr = rd32be(p + off + 6);
    off += olen;
  }
  /*  JA4T: window_options_mss_wscale.  */
  q = s->ja4t + sprintf(s->ja4t, "%u_", s->win);
  for (off = 0; off < s->nopts; off++) q += sprintf(q, off ? "-%u" : "%u", s->opts[off]);
  if (!s->nopts) q += sprintf(q, "00");
  q += s->mss >= 0 ? sprintf(q, "_%d", s->mss) : sprintf(q, "_00");
  if (s->wscale >= 0) sprintf(q, "_%d", s->wscale);
  else sprintf(q, "_00");
  return 0;
}

/*  HTTP/2.  */

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN 24

/*  The HPACK Huffman codes (RFC 7541, appendix B) of the characters of the
    pseudo-header names, to recognise them in Huffman coded literal names.  */
static const struct { char c;  u8 len, code; } h2_huff[] = {
  { ':', 7, 0x5c }, { 'a', 5, 0x03 }, { 'c', 5, 0x04 }, { 'd', 6, 0x24 }, { 'e', 5, 0x05 },
  { 'h', 6, 0x27 }, { 'i', 5, 0x06 }, { 'm', 6, 0x29 }, { 'o', 5, 0x07 }, { 'p', 6, 0x2b },
  { 'r', 6, 0x2c }, { 's', 5, 0x08 }, { 't', 5, 0x09 }, { 'u', 6, 0x2d }, { 'y', 7, 0x7a },
};

static const struct { const char * name;  char letter; } h2_pseudo[] = {
  { ":method", 'm' }, { ":authority", 'a' }, { ":scheme", 's' }, { ":path", 'p' },
};

/*  Encode s, made of the characters above, padded with ones as RFC 7541 says.  */
static sz h2_huff_enc(const char * s, u8 * out) {
  u32 acc = 0;  unsigned bits = 0, i;  sz n = 0;
  for (; *s; s++) {
    for (i = 0; h2_huff[i].c != *s; i++);
    acc = acc << h2_huff[i].len | h2_huff[i].code;  bits += h2_huff[i].len;
    while (bits >= 8) { bits -= 8;  out[n++] = (u8) (acc >> bits); }
    acc &= (1u << bits) - 1;
  }
  if (bits) out[n++] = (u8) (acc << (8 - bits) | 0xff >> bits);
  return n;
}

/*  The letter of a pseudo-header name, '?' for another one, 0 for a header.  */
static char h2_name_class(const u8 * s, sz len, int huff) {
  u8 enc[16];  sz i;
  for (i = 0; i < ARRAY_LEN(h2_pseudo); i++)
    if (huff ? h2_huff_enc(h2_pseudo[i].name, enc) == len && !memcmp(enc, s, len)
             : strlen(h2_pseudo[i].name) == len && !memcmp(h2_pseudo[i].name, s, len))
      return h2_pseudo[i].letter;
  if (!len) return 0;
  return (huff ? s[0] >> 1 == 0x5c : s[0] == ':') ? '?' : 0;
}

/*  Static entries 1-14 are pseudo-headers; dyn holds the classes of the
    entries this block added, newest last.  */
static char h2_index_class(u32 idx, const char * dyn, unsigned ndyn) {
  if (idx >= 1 && idx <= 14) return "?ammppss???????"[idx];
  if (idx >= 62 && idx - 62 < ndyn) return dyn[ndyn - 1 - (idx - 62)];
  return 0;
}

static int hp_int(const u8 ** pp, const u8 * end, unsigned prefix, u32 * out) {
  const u8 * p = *pp;
  u64 v;  unsigned m = 0, max = (1u << prefix) - 1;
  if (p >= end) return -1;
  v = *p++ & max;
  if (v == max)
    for (;;) {
      if (p >= end || m > 28) return -1;
      v += (u64) (*p & 127) << m;  m += 7;
      if (!(*p++ & 128)) break;
    }
  if (v > 0xffffffffu) return -1;
  *pp = p;  *out = (u32) v;
  return 0;
}

static int hp_str(const u8 ** pp, const u8 * end, const u8 ** s, u32 * len, int * huff) {
  if (*pp >= end) return -1;
  *huff = **pp >> 7;
  if (hp_int(pp, end, 7, len) || *len > (sz) (end - *pp)) return -1;
  *s = *pp;  *pp += *len;
  return 0;
}

static void h2_cat(char * buf, sz cap, const char * fmt, ...) {
  sz n = strlen(buf);
  va_list ap;
  if (n + 1 >= cap) return;
  va_start(ap, fmt);  vsnprintf(buf + n, cap - n, fmt, ap);  va_end(ap);
}

static void h2_block(fer_h2_t * h) {
  const u8 * p = h->hb, * end = p + h->hblen, * s;
  char dyn[64], cls;
  unsigned ndyn = 0, incr;
  u32 idx, len;
  int huff;
  while (p < end) {
    if ((*p & 0xe0) == 0x20) {           /*  Table size update.  */
      if (hp_int(&p, end, 5, &idx)) break;
      continue;
    }
    if (*p & 0x80) {
      if (hp_int(&p, end, 7, &idx)) break;
      cls = h2_index_class(idx, dyn, ndyn);
    } else {
      incr = (*p & 0xc0) == 0x40;
      if (hp_int(&p, end, incr ? 6 : 4, &idx)) break;
      if (idx) cls = h2_index_class(idx, dyn, ndyn);
      else if (hp_str(&p, end, &s, &len, &huff)) break;
      else cls = h2_name_class(s, len, huff);
      if (hp_str(&p, end, &s, &len, &huff)) break;
      if (incr && ndyn < sizeof dyn) dyn[ndyn++] = cls;
    }
    if (!cls) break;
    h2_cat(h->pseudo, sizeof h->pseudo, h->pseudo[0] ? ",%c" : "%c", cls);
  }
}

static void h2_block_done(fer_h2_t * h) {
  h->in_block = 0;  h->block_done = 1;
  if (h->hb) h2_block(h);
  free(h->hb);  h->hb = NULL;
}

static void h2_frame_start(fer_h2_t * h) {
  h->collect = (h->type == 1 && !h->headers_seen) || (h->type == 9 && h->in_block);
  if (h->type == 1 && !h->headers_seen && !h->hb) { h->hb = malloc(FER_H2_HBMAX);  h->hblen = 0; }
}

static void h2_frame_end(fer_h2_t * h) {
  const u8 * p = h->pb;
  sz n = MIN(h->len, sizeof h->pb), i, off = 0, pad = 0, e;
  h->frames[h->type < FER_H2_NTYPES - 1 ? h->type : FER_H2_NTYPES - 1]++;
  switch (h->type) {
    case 1:                               /*  HEADERS  */
      if (h->sid > h->max_sid) h->max_sid = h->sid;
      if (h->headers_seen) break;
      h->headers_seen = 1;
      if (h->flags & 0x08 && n >= 1) { pad = p[0];  off = 1; }
      if (h->flags & 0x20 && n >= off + 5) {
        snprintf(h->hprio, sizeof h->hprio, "%u:%u:%u", p[off] >> 7, rd32be(p + off) & 0x7fffffff, p[off + 4] + 1);
        h->hprio_seen = 1;  off += 5;
      }
      if (h->hb) {
        e = MIN(h->len >= pad ? h->len - pad : 0, h->hblen);
        h->hblen = e > off ? e - off : 0;
        memmove(h->hb, h->hb + off, h->hblen);
      }
      h->in_block = 1;
      if (h->flags & 0x04) h2_block_done(h);
      break;
    case 9:                               /*  CONTINUATION  */
      if (h->in_block && h->flags & 0x04) h2_block_done(h);
      break;
    case 2:                               /*  PRIORITY  */
      if (!h->headers_seen && n >= 5)
        h2_cat(h->prio, sizeof h->prio, h->prio[0] ? ",%u:%u:%u:%u" : "%u:%u:%u:%u",
               h->sid, p[0] >> 7, rd32be(p) & 0x7fffffff, p[4] + 1);
      break;
    case 4:                               /*  SETTINGS, not an ACK  */
      if (h->flags & 0x01 || h->settings_seen) break;
      h->settings_seen = 1;
      for (i = 0; i + 6 <= n; i += 6)
        h2_cat(h->settings, sizeof h->settings, i ? ";%u:%u" : "%u:%u", rd16be(p + i), rd32be(p + i + 2));
      break;
    case 7:                               /*  GOAWAY  */
      if (!h->goaway_seen && n >= 8) { h->goaway_code = rd32be(p + 4);  h->goaway_seen = 1; }
      break;
    case 8:                               /*  WINDOW_UPDATE  */
      if (!h->headers_seen && !h->wu_seen && !h->sid && n >= 4) { h->wu = rd32be(p) & 0x7fffffff;  h->wu_seen = 1; }
      break;
  }
}

int fer_h2_feed(fer_h2_t * h, const u8 * p, sz n) {
  const u8 * end = p + n;
  sz k;
  if (h->state == FER_H2_OFF) return -1;
  h->bytes += n;
  while (p < end)
    switch (h->state) {
      case FER_H2_PREFACE:
        k = MIN((sz) (end - p), H2_PREFACE_LEN - h->got);
        if (memcmp(p, H2_PREFACE + h->got, k)) { h->state = FER_H2_OFF;  return -1; }
        p += k;  h->got += (u32) k;
        if (h->got == H2_PREFACE_LEN) { h->is_h2 = 1;  h->state = FER_H2_HEAD;  h->fhlen = 0; }
        break;
      case FER_H2_HEAD:
        k = MIN((sz) (end - p), 9u - h->fhlen);
        memcpy(h->fh + h->fhlen, p, k);  h->fhlen += (u8) k;  p += k;
        if (h->fhlen < 9) break;
        h->len = (u32) h->fh[0] << 16 | h->fh[1] << 8 | h->fh[2];
        h->type = h->fh[3];  h->flags = h->fh[4];  h->sid = rd32be(h->fh + 5) & 0x7fffffff;
        h->got = 0;  h->fhlen = 0;
        h2_frame_start(h);
        if (h->len) h->state = FER_H2_BODY;
        else h2_frame_end(h);
        break;
      case FER_H2_BODY:
        k = MIN((sz) (end - p), h->len - h->got);
        if (h->got < sizeof h->pb && h->type) memcpy(h->pb + h->got, p, MIN(k, sizeof h->pb - h->got));
        if (h->collect && h->hb) {
          sz m = MIN(k, FER_H2_HBMAX - h->hblen);
          memcpy(h->hb + h->hblen, p, m);  h->hblen += m;
        }
        h->got += (u32) k;  p += k;
        if (h->got == h->len) { h2_frame_end(h);  h->state = FER_H2_HEAD; }
        break;
    }
  return 0;
}

void fer_h2_finish(fer_h2_t * h) {
  if (h->in_block) h2_block_done(h);
  free(h->hb);  h->hb = NULL;
}

void fer_h2_fp(const fer_h2_t * h, char * out, sz cap) {
  char wu[16] = "00";
  if (h->wu_seen) snprintf(wu, sizeof wu, "%u", h->wu);
  snprintf(out, cap, "%s|%s|%s|%s", h->settings, wu, h->prio[0] ? h->prio : "0", h->pseudo);
}

static const char * secrets[] = {
  "access_token", "token", "key", "api_key", "password", "passwd", "secret", "sig",
  "signature", "code", "state", "login_token", "session", "auth", NULL
};

static int is_secret(const u8 * k, sz n) {
  const char ** s;
  for (s = secrets; *s; s++) if (strlen(*s) == n && !strncasecmp((const char *) k, *s, n)) return 1;
  return 0;
}

/*  A query ends at '#', or at a space when src is a request line.  */
static int qend(u8 c) { return c == ' ' || c == '#'; }

sz fer_scrub(const u8 * src, sz len, u8 * dst, sz dstcap, int whole_is_query) {
  sz i = 0, o = 0, j, ks, ke, vs;
#define PUT(c) do { if (o < dstcap) dst[o] = (u8) (c);  o++; } while (0)
  if (!whole_is_query) {
    for (; i < len && src[i] != '?'; i++) PUT(src[i]);
    if (i == len) return MIN(o, dstcap);
    PUT('?');  i++;
  }
  while (i < len && !qend(src[i])) {
    for (ks = i; i < len && src[i] != '=' && src[i] != '&' && src[i] != ';' && !qend(src[i]); i++);
    ke = i;
    for (j = ks; j < ke; j++) PUT(src[j]);
    if (i < len && src[i] == '=') {
      PUT('=');
      for (vs = ++i; i < len && src[i] != '&' && src[i] != ';' && !qend(src[i]); i++);
      if (is_secret(src + ks, ke - ks)) {
        char t[32];
        int n = snprintf(t, sizeof t, "<len:%zu>", i - vs);
        for (j = 0; j < (sz) n; j++) PUT(t[j]);
      } else for (j = vs; j < i; j++) PUT(src[j]);
    }
    if (i < len && (src[i] == '&' || src[i] == ';')) { PUT(src[i]);  i++; }
  }
  for (; i < len; i++) PUT(src[i]);
#undef PUT
  return MIN(o, dstcap);
}

void fer_khash(const u8 * key, sz keylen, const u8 * data, sz len, u8 out[8]) {
  u8 md[EVP_MAX_MD_SIZE];  unsigned n = 0;
  HMAC(EVP_sha256(), key, (int) keylen, data, len, md, &n);
  memcpy(out, md, 8);
}

int fer_intel_open(fer_intel_t * in, const char * path, char * err, sz errlen) {
  int fd;  struct stat st;  const u8 * m;  u32 o4, o6, oa;
  memset(in, 0, sizeof *in);
  if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1) {
    snprintf(err, errlen, "open(\"%s\") failed: %m", path);
    return -1;
  }
  if (fstat(fd, &st) == -1 || st.st_size < 64) {
    snprintf(err, errlen, "\"%s\" is too small", path);
    close(fd);
    return -1;
  }
  in->map = mmap(NULL, (sz) st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  close(fd);
  if (in->map == MAP_FAILED) {
    in->map = NULL;
    snprintf(err, errlen, "mmap(\"%s\") failed: %m", path);
    return -1;
  }
  in->size = (sz) st.st_size;  m = in->map;
  if (memcmp(m, "FERI", 4) || rd32le(m + 4) != 1) {
    snprintf(err, errlen, "\"%s\": bad magic or version", path);
    fer_intel_close(in);
    return -1;
  }
  in->version = rd32le(m + 16);  in->n4 = rd32le(m + 20);  in->n6 = rd32le(m + 24);  in->nasn = rd32le(m + 28);
  o4 = rd32le(m + 32);  o6 = rd32le(m + 36);  oa = rd32le(m + 40);
  if ((u64) o4 + (u64) in->n4 * 24 > in->size || (u64) o6 + (u64) in->n6 * 48 > in->size ||
      (u64) oa + (u64) in->nasn * 16 > in->size) {
    snprintf(err, errlen, "\"%s\": tables exceed file size", path);
    fer_intel_close(in);
    return -1;
  }
  in->t4 = m + o4;  in->t6 = m + o6;  in->tasn = m + oa;
  return 0;
}

void fer_intel_close(fer_intel_t * in) {
  if (in->map) munmap(in->map, in->size);
  memset(in, 0, sizeof *in);
}

u64 fer_intel_ip(const fer_intel_t * in, const u8 * addr, sz alen, unsigned * score) {
  sz lo = 0, hi, mid;  const u8 * e;  u32 a;
  *score = 0;
  if (!in->map) return 0;
  if (alen == 16 && !memcmp(addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12)) addr += 12, alen = 4;
  if (alen == 4) {
    a = rd32be(addr);
    for (hi = in->n4; lo < hi;) {
      mid = lo + (hi - lo) / 2;
      if (rd32le(in->t4 + mid * 24) <= a) lo = mid + 1;
      else hi = mid;
    }
    if (!lo || a > rd32le((e = in->t4 + (lo - 1) * 24) + 4)) return 0;
    *score = e[16];
    return rd64le(e + 8);
  }
  if (alen != 16) return 0;
  for (hi = in->n6; lo < hi;) {
    mid = lo + (hi - lo) / 2;
    if (memcmp(in->t6 + mid * 48, addr, 16) <= 0) lo = mid + 1;
    else hi = mid;
  }
  if (!lo || memcmp(addr, (e = in->t6 + (lo - 1) * 48) + 16, 16) > 0) return 0;
  *score = e[40];
  return rd64le(e + 32);
}

u64 fer_intel_asn(const fer_intel_t * in, u32 asn) {
  sz lo = 0, hi = in->nasn, mid;  u32 v;
  if (!in->map || !asn) return 0;
  while (lo < hi) {
    mid = lo + (hi - lo) / 2;
    if ((v = rd32le(in->tasn + mid * 16)) == asn) return rd64le(in->tasn + mid * 16 + 8);
    if (v < asn) lo = mid + 1;
    else hi = mid;
  }
  return 0;
}
