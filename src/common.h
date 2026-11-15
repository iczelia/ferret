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

#ifndef FER_COMMON_H
#define FER_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t  u8;  typedef int8_t  i8;
typedef uint16_t u16;  typedef int16_t i16;
typedef uint32_t u32;  typedef int32_t i32;
typedef uint64_t u64;  typedef int64_t i64;
typedef size_t   sz;

#define INLINE __inline__ __attribute__((__always_inline__))

static INLINE u16 rd16be(const u8 * p) { return (u16) (p[0] << 8 | p[1]); }
static INLINE u32 rd32be(const u8 * p) {
  return (u32) p[0] << 24 | (u32) p[1] << 16 | (u32) p[2] << 8 | p[3];
}
static INLINE u32 rd32le(const u8 * p) {
  return p[0] | (u32) p[1] << 8 | (u32) p[2] << 16 | (u32) p[3] << 24;
}
static INLINE void wr32le(u8 * p, u32 v) {
  p[0] = (u8) v;  p[1] = (u8) (v >> 8);  p[2] = (u8) (v >> 16);  p[3] = (u8) (v >> 24);
}
static INLINE u64 rd64le(const u8 * p) { return rd32le(p) | (u64) rd32le(p + 4) << 32; }
static INLINE void wr64le(u8 * p, u64 v) { wr32le(p, (u32) v);  wr32le(p + 4, (u32) (v >> 32)); }

#define Fi(n, ...) for (i = 0; i < (n); i++) {  __VA_ARGS__; }
#define Fj(n, ...) for (j = 0; j < (n); j++) {  __VA_ARGS__; }

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#define ARRAY_LEN(a) (sizeof (a) / sizeof *(a))

#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)

#endif
