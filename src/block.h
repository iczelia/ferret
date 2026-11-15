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

#ifndef FER_BLOCK_H
#define FER_BLOCK_H

#include <stdlib.h>

#include "common.h"

#define FER_FORMAT_VERSION 1
#define FER_ROW_HDR 8

typedef struct { const char * name;  u8 type; } fer_col_t;
typedef struct { u16 id;  const char * name;  const fer_col_t * cols;  unsigned ncols; } fer_table_t;
typedef struct { const char * key, * value; } fer_kv_t;
extern const fer_table_t fer_tables[3];

/*  Turn the staging rows in rows[0, len) into one compressed block per table
    and append them to <dir>/YYYY-MM-DD.fer, named for the UTC date of now_us.
    Returns 0, or -1 with a message in err.  */
int fer_write_blocks(const char * dir, const u8 * rows, sz len, const fer_kv_t * meta, unsigned nmeta,
                     u32 preset, i64 now_us, char * err, sz errlen);

/*  Delete the day files more than `days' days old.  Returns how many went,
    or -1 if dir cannot be read.  */
int fer_retention_sweep(const char * dir, int days, i64 now_us);

typedef struct { u8 * buf;  sz len, cap, max;  u16 nfields;  int truncated; } fer_rowbuf_t;

static inline int fer_rb_reserve(fer_rowbuf_t * rb, sz n) {
  sz cap;  u8 * p;
  if (rb->len + n > rb->max) { rb->truncated = 1;  return -1; }
  if (rb->len + n <= rb->cap) return 0;
  for (cap = rb->cap ? rb->cap : KiB(4); cap < rb->len + n; cap *= 2);
  if (!(p = realloc(rb->buf, cap))) { rb->truncated = 1;  return -1; }
  rb->buf = p;  rb->cap = cap;
  return 0;
}

static inline void fer_row_begin(fer_rowbuf_t * rb, u8 table) {
  rb->len = 0;  rb->nfields = 0;  rb->truncated = 0;
  if (fer_rb_reserve(rb, FER_ROW_HDR)) return;
  memset(rb->buf, 0, FER_ROW_HDR);
  rb->buf[4] = table;  rb->len = FER_ROW_HDR;
}

static inline void fer_row_num(fer_rowbuf_t * rb, unsigned col, i64 v) {
  if (rb->len < FER_ROW_HDR || fer_rb_reserve(rb, 9)) return;
  rb->buf[rb->len] = (u8) col;  memcpy(rb->buf + rb->len + 1, &v, 8);
  rb->len += 9;  rb->nfields++;
}

static inline void fer_row_bytes(fer_rowbuf_t * rb, unsigned col, const void * p, sz n) {
  u32 n32;
  if (!p || rb->len < FER_ROW_HDR || n > 0xffffffffu || fer_rb_reserve(rb, 5 + n)) return;
  n32 = (u32) n;
  rb->buf[rb->len] = (u8) col;  memcpy(rb->buf + rb->len + 1, &n32, 4);
  if (n) memcpy(rb->buf + rb->len + 5, p, n);
  rb->len += 5 + n;  rb->nfields++;
}

static inline void fer_row_str(fer_rowbuf_t * rb, unsigned col, const char * s) {
  if (s) fer_row_bytes(rb, col, s, strlen(s));
}

/*  Fill in the header; returns the row length, 0 if the row is unusable.  */
static inline sz fer_row_end(fer_rowbuf_t * rb) {
  u32 n = (u32) rb->len;
  if (rb->len < FER_ROW_HDR) return 0;
  memcpy(rb->buf, &n, 4);  memcpy(rb->buf + 6, &rb->nfields, 2);
  return rb->len;
}

#endif
