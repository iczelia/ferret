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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <netinet/tcp.h>
#include <maxminddb.h>
#include <lzma.h>

#include "common.h"
#include "block.h"
#include "schema.h"
#include "feat.h"

#define FER_MODULE_VERSION "0.1.0"

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif
#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif

#define FER_VAL_MAX 4096                 /*  One captured header value.  */
#define FER_LINE_MAX 8192                /*  Request line, path, args.  */
#define FER_STALE_US (15 * 60 * 1000000LL)

enum { FER_BUF_IDLE, FER_BUF_FILL, FER_BUF_FLUSHING };

/*  struct tcp_info of linux/tcp.h, whose ABI only ever grows at the end.  */
typedef struct {
  u8 state, ca_state, retransmits, probes, backoff, options, wscale, misc;
  u32 rto, ato, snd_mss, rcv_mss, unacked, sacked, lost, retrans, fackets;
  u32 last_data_sent, last_ack_sent, last_data_recv, last_ack_recv;
  u32 pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, snd_cwnd, advmss, reordering;
  u32 rcv_rtt, rcv_space, total_retrans;
  u64 pacing_rate, max_pacing_rate, bytes_acked, bytes_received;
  u32 segs_out, segs_in, notsent_bytes, min_rtt, data_segs_in, data_segs_out;
  u64 delivery_rate;
} fer_tcp_info_t;

#define TI_HAS(len, f) ((len) >= offsetof(fer_tcp_info_t, f) + sizeof(((fer_tcp_info_t *) 0)->f))

typedef struct {
  sz used;
  i64 first_us;
  ngx_atomic_t state;
  ngx_pid_t owner;
  i64 flush_start_us;
  u32 dropped;
  u_char * data;
} fer_shbuf_t;

typedef struct {
  u32 magic, schema_hash;
  ngx_slab_pool_t * shpool;
  sz bufsize;
  ngx_uint_t active;
  fer_shbuf_t b[2];
  ngx_atomic_t conn_seq, flush_seq;
} fer_shm_t;

typedef struct {
  ngx_str_t dir;
  ngx_shm_zone_t * zone;
  sz block_size;
  ngx_msec_t flush_interval;
  u32 preset;
  ngx_int_t retention;
  ngx_str_t geo_db, asn_db, intel_db, hash_key_file, hash_key;
  ngx_array_t * capture_headers;       /*  Of lowercase ngx_str_t.  */
  ngx_flag_t save_syn, rdns;
  ngx_msec_t rdns_timeout;
  ngx_resolver_t * resolver;
#if (NGX_THREADS)
  ngx_thread_pool_t * thread_pool;
  ngx_str_t thread_pool_name;
#endif
  ngx_uint_t active;
} fer_main_conf_t;

typedef struct {
  ngx_flag_t enable;
  ngx_array_t * traps;
  ngx_http_complex_value_t * tag;
} fer_loc_conf_t;

typedef struct {
  ngx_resolver_ctx_t * ctx;
  ngx_resolver_t * resolver;
  struct sockaddr_storage sa;
  socklen_t salen;
  u_char caddr[16];
  sz caddr_len;
  i64 start_us, end_us;
  ngx_msec_t budget;
  const char * status;
  u_char name[256];
  sz name_len;
  int fcrdns;                          /*  -1 unknown.  */
  unsigned done : 1, closed : 1;
  u_char * row;
  sz row_len;
} fer_rdns_t;

typedef struct {
  ngx_connection_t * c;
  u64 id, bytes_in, bytes_out;
  i64 ts_accept, ts_hello, ts_hs, prev_end;
  u32 nreq;
  ngx_uint_t last_status;
  u_char caddr[16], saddr[16];
  sz caddr_len, saddr_len;
  ngx_uint_t cport, lport;
  u_char * syn_raw;
  sz syn_len;
  fer_syn_t syn;
  fer_tcp_info_t ti;
  socklen_t ti_len;
  u32 th_rtt, th_retr;
  unsigned syn_ok : 1, th_ok : 1, listen_tls : 1, hello_seen : 1, handshaked : 1, reused : 1, geo_ok : 1;
  fer_hello_t hello;
  u16 hello_legacy;
  u_char * h_ciphers, * h_exts, * h_comp;
  sz h_ciphers_len, h_exts_len, h_comp_len;
  ngx_uint_t h_sid_len;
  ngx_str_t tls_ver, tls_cipher, tls_group, tls_alpn;
  ngx_uint_t alert_sent, alert_recv;
  ngx_str_t country, region, city, asorg;
  i64 lat_e4, lon_e4;
  u32 asn;
  u64 intel;
  unsigned ipsum;
  fer_rdns_t * rdns;
  fer_h2_t h2;
  ngx_connection_handler_pt ssl_handler;  /*  Until the TLS handshake is done.  */
} fer_conn_t;

typedef struct {
  ngx_uint_t idx;
  sz len;
  i64 now_us;
  ngx_int_t retention;
  u32 preset;
  fer_kv_t meta[8];
  unsigned nmeta;
  char metabuf[512], dir[1024], err[256];
  int rc;
} fer_flush_t;

static ngx_int_t fer_preconfiguration(ngx_conf_t * cf);
static ngx_int_t fer_postconfiguration(ngx_conf_t * cf);
static void * fer_create_main_conf(ngx_conf_t * cf);
static char * fer_init_main_conf(ngx_conf_t * cf, void * conf);
static void * fer_create_loc_conf(ngx_conf_t * cf);
static char * fer_merge_loc_conf(ngx_conf_t * cf, void * parent, void * child);
static char * fer_set_shm(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static char * fer_set_preset(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static char * fer_set_retention(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static char * fer_set_list(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
#if (NGX_THREADS)
static char * fer_set_thread_pool(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
#endif
static ngx_int_t fer_init_module(ngx_cycle_t * cycle);
static ngx_int_t fer_init_process(ngx_cycle_t * cycle);
static void fer_exit_process(ngx_cycle_t * cycle);
static void fer_exit_master(ngx_cycle_t * cycle);
static ssize_t fer_recv_plain(ngx_connection_t * c, u_char * buf, size_t size);

#define MAIN NGX_HTTP_MAIN_CONF
#define ANY (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF)
#define MOFF NGX_HTTP_MAIN_CONF_OFFSET
#define LOFF NGX_HTTP_LOC_CONF_OFFSET
#define MO(f) offsetof(fer_main_conf_t, f)
#define LO(f) offsetof(fer_loc_conf_t, f)

/*  fer_set_list lowercases the values when post is set.  */
static ngx_command_t fer_commands[] = {
  { ngx_string("ferret"), ANY | NGX_CONF_FLAG, ngx_conf_set_flag_slot, LOFF, LO(enable), NULL },
  { ngx_string("ferret_path"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_str_slot, MOFF, MO(dir), NULL },
  { ngx_string("ferret_shm"), MAIN | NGX_CONF_TAKE2, fer_set_shm, MOFF, 0, NULL },
  { ngx_string("ferret_block_size"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_size_slot, MOFF, MO(block_size), NULL },
  { ngx_string("ferret_flush_interval"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_msec_slot, MOFF, MO(flush_interval), NULL },
  { ngx_string("ferret_xz_preset"), MAIN | NGX_CONF_TAKE1, fer_set_preset, MOFF, 0, NULL },
  { ngx_string("ferret_retention"), MAIN | NGX_CONF_TAKE1, fer_set_retention, MOFF, 0, NULL },
#if (NGX_THREADS)
  { ngx_string("ferret_thread_pool"), MAIN | NGX_CONF_TAKE1, fer_set_thread_pool, MOFF, 0, NULL },
#endif
  { ngx_string("ferret_geo_db"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_str_slot, MOFF, MO(geo_db), NULL },
  { ngx_string("ferret_asn_db"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_str_slot, MOFF, MO(asn_db), NULL },
  { ngx_string("ferret_intel_db"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_str_slot, MOFF, MO(intel_db), NULL },
  { ngx_string("ferret_hash_key"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_str_slot, MOFF, MO(hash_key_file), NULL },
  { ngx_string("ferret_capture_header"), MAIN | NGX_CONF_1MORE, fer_set_list, MOFF, MO(capture_headers), (void *) 1 },
  { ngx_string("ferret_save_syn"), MAIN | NGX_CONF_FLAG, ngx_conf_set_flag_slot, MOFF, MO(save_syn), NULL },
  { ngx_string("ferret_rdns"), MAIN | NGX_CONF_FLAG, ngx_conf_set_flag_slot, MOFF, MO(rdns), NULL },
  { ngx_string("ferret_rdns_timeout"), MAIN | NGX_CONF_TAKE1, ngx_conf_set_msec_slot, MOFF, MO(rdns_timeout), NULL },
  { ngx_string("ferret_trap"), ANY | NGX_CONF_1MORE, fer_set_list, LOFF, LO(traps), NULL },
  { ngx_string("ferret_tag"), ANY | NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, LOFF, LO(tag), NULL },
  ngx_null_command
};

static ngx_http_module_t fer_module_ctx = {
  fer_preconfiguration, fer_postconfiguration, fer_create_main_conf, fer_init_main_conf,
  NULL, NULL, fer_create_loc_conf, fer_merge_loc_conf
};

ngx_module_t ngx_http_ferret_module = {
  NGX_MODULE_V1, &fer_module_ctx, fer_commands, NGX_HTTP_MODULE,
  NULL, fer_init_module, fer_init_process, NULL, NULL, fer_exit_process, fer_exit_master,
  NGX_MODULE_V1_PADDING
};

static fer_shm_t * fer_shm;
static fer_main_conf_t * fer_mcf;              /*  Of the running cycle, in workers.  */
static ngx_connection_handler_pt fer_orig_handler;
static fer_rowbuf_t fer_rb = { NULL, 0, 0, MiB(1), 0, 0 };
static ngx_event_t fer_timer;
static ngx_connection_t fer_timer_conn;
static MMDB_s fer_geo, fer_asn;
static unsigned fer_geo_open, fer_asn_open;
static fer_intel_t fer_intel;
static u32 fer_schema_hash;
static char fer_hostname[256];
static fer_conn_t * fer_accepting;             /*  Inside the wrapped accept handler.  */
static int fer_ssl_idx = -1;
#if (NGX_HTTP_SSL)
static void (*fer_orig_info_cb)(const SSL * ssl, int where, int ret);
#endif

/*  Fields of the one row being built.  */
#define N(col, v) fer_row_num(&fer_rb, col, (i64) (v))
#define B(col, p, n) fer_row_bytes(&fer_rb, col, p, n)
#define S(col, s) fer_row_str(&fer_rb, col, s)

static void V(unsigned col, ngx_str_t * s) { if (s && s->data && s->len) B(col, s->data, s->len); }
static void C(unsigned col, u_char * p, sz n, sz cap) { if (p && n) B(col, p, MIN(n, cap)); }
static void Q(unsigned col, u_char * p, sz n, int whole_query) {
  u_char buf[FER_LINE_MAX];
  if (p && n) B(col, buf, fer_scrub(p, n, buf, sizeof buf, whole_query));
}

static i64 fer_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (i64) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void fer_host(void) {
  if (gethostname(fer_hostname, sizeof fer_hostname - 1)) strcpy(fer_hostname, "unknown");
}

static void fer_addr(struct sockaddr * sa, u_char * out, sz * len, ngx_uint_t * port) {
  ngx_uint_t pt = 0;
  *len = 0;
  if (sa && sa->sa_family == AF_INET) {
    struct sockaddr_in * s4 = (struct sockaddr_in *) sa;
    memcpy(out, &s4->sin_addr, 4);  *len = 4;  pt = ntohs(s4->sin_port);
  }
#if (NGX_HAVE_INET6)
  if (sa && sa->sa_family == AF_INET6) {
    struct sockaddr_in6 * s6 = (struct sockaddr_in6 *) sa;
    *len = IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr) ? 4 : 16;
    memcpy(out, s6->sin6_addr.s6_addr + 16 - *len, *len);  pt = ntohs(s6->sin6_port);
  }
#endif
  if (port) *port = pt;
}

static void fer_tcp_info(int fd, fer_tcp_info_t * ti, socklen_t * len) {
  *len = sizeof *ti;  memset(ti, 0, sizeof *ti);
  if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, ti, len) == -1) *len = 0;
}

/*  Flushing.  */

static void fer_idle(fer_shbuf_t * b) {
  b->used = 0;  b->dropped = 0;
  ngx_memory_barrier();
  b->state = FER_BUF_IDLE;
}

static void fer_flush_init(fer_flush_t * f, fer_main_conf_t * mcf, ngx_uint_t idx) {
  fer_shbuf_t * b = &fer_shm->b[idx];
  char * p = f->metabuf, * end = p + sizeof f->metabuf;
  u64 seq = ngx_atomic_fetch_add(&fer_shm->flush_seq, 1);
  f->idx = idx;  f->len = b->used;  f->now_us = fer_now();
  f->retention = mcf->retention;  f->preset = mcf->preset;  f->nmeta = 0;
  ngx_cpystrn((u_char *) f->dir, mcf->dir.data, MIN(mcf->dir.len + 1, sizeof f->dir));
#define META(k, ...) { \
    int w = snprintf(p, (sz) (end - p), __VA_ARGS__); \
    if (w >= 0 && p + w < end) { f->meta[f->nmeta].key = k;  f->meta[f->nmeta++].value = p;  p += w + 1; } }
  META("host", "%s", fer_hostname);
  META("module_version", "%s", FER_MODULE_VERSION);
  META("flush_seq", "%llu", (unsigned long long) seq);
  META("dropped_rows", "%u", b->dropped);
  META("intel_version", "%u", fer_intel.version);
  META("geo_build", "%llu", fer_geo_open ? (unsigned long long) fer_geo.metadata.build_epoch : 0ULL);
  META("asn_build", "%llu", fer_asn_open ? (unsigned long long) fer_asn.metadata.build_epoch : 0ULL);
#undef META
}

static void fer_flush_run(void * data, ngx_log_t * log) {
  fer_flush_t * f = data;
  f->rc = fer_write_blocks(f->dir, fer_shm->b[f->idx].data, f->len, f->meta, f->nmeta,
                           f->preset, f->now_us, f->err, sizeof f->err);
  if (f->retention >= 0) fer_retention_sweep(f->dir, (int) f->retention, f->now_us);
}

static void fer_flush_sync(fer_main_conf_t * mcf, ngx_uint_t idx, ngx_log_t * log) {
  fer_flush_t f;
  ngx_core_conf_t * ccf;
  char path[1100];
  struct tm tm;
  time_t t;
  fer_flush_init(&f, mcf, idx);  fer_flush_run(&f, log);
  if (f.rc) ngx_log_error(NGX_LOG_ERR, log, 0, "ferret: flush failed: %s", f.err);
  if (geteuid() == 0) {
    t = (time_t) (f.now_us / 1000000);  gmtime_r(&t, &tm);
    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);
    if (ccf && ccf->user != (ngx_uid_t) NGX_CONF_UNSET_UINT
        && snprintf(path, sizeof path, "%s/%04d-%02d-%02d.fer", f.dir, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday) < (int) sizeof path
        && chown(path, ccf->user, ccf->group) == -1 && ngx_errno != NGX_ENOENT)
      ngx_log_error(NGX_LOG_WARN, log, ngx_errno, "ferret: chown(\"%s\") failed", path);
  }
  fer_idle(&fer_shm->b[idx]);
}

#if (NGX_THREADS)
static void fer_flush_thread(void * data, ngx_log_t * log) {
  fer_flush_t * f = data;
  fer_flush_run(f, log);
  /*  Released here rather than in the completion event: a worker that exits
      on reload joins its threads but never runs posted events.  */
  fer_idle(&fer_shm->b[f->idx]);
}

static void fer_flush_done(ngx_event_t * ev) {
  ngx_thread_task_t * task = ev->data;
  fer_flush_t * f = task->ctx;
  if (f->rc) ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ferret: flush failed: %s", f->err);
  ngx_free(task);
}
#endif

static void fer_post_flush(ngx_int_t idx) {
#if (NGX_THREADS)
  ngx_thread_task_t * task;
#endif
  if (idx < 0 || !fer_mcf) return;
#if (NGX_THREADS)
  if (fer_mcf->thread_pool && (task = ngx_calloc(sizeof *task + sizeof(fer_flush_t), ngx_cycle->log))) {
    task->ctx = task + 1;
    task->handler = fer_flush_thread;
    task->event.handler = fer_flush_done;  task->event.data = task;
    /*  The length is stable: nobody appends to a FLUSHING buffer.  */
    fer_flush_init(task->ctx, fer_mcf, (ngx_uint_t) idx);
    if (ngx_thread_task_post(fer_mcf->thread_pool, task) == NGX_OK) return;
    ngx_free(task);
  }
#endif
  fer_flush_sync(fer_mcf, (ngx_uint_t) idx, ngx_cycle->log);
}

/*  Under the lock: retire the active buffer, return its index or -1.  */
static ngx_int_t fer_swap(i64 now) {
  ngx_uint_t a = fer_shm->active;
  fer_shbuf_t * ab = &fer_shm->b[a], * ob = &fer_shm->b[a ^ 1];
  if (ob->state != FER_BUF_IDLE || !ab->used) return -1;
  ab->state = FER_BUF_FLUSHING;  ab->owner = ngx_pid;  ab->flush_start_us = now;
  ob->used = 0;  ob->dropped = 0;  ob->first_us = 0;  ob->state = FER_BUF_FILL;
  fer_shm->active = a ^ 1;
  return (ngx_int_t) a;
}

static void fer_append(const u_char * row, sz len) {
  fer_shbuf_t * b;
  ngx_int_t f1 = -1, f2 = -1;
  i64 now;
  if (!fer_shm || !len) return;
  now = fer_now();
  ngx_shmtx_lock(&fer_shm->shpool->mutex);
  b = &fer_shm->b[fer_shm->active];
  if (b->used + len > fer_shm->bufsize) { f1 = fer_swap(now);  b = &fer_shm->b[fer_shm->active]; }
  if (b->used + len > fer_shm->bufsize) b->dropped++;
  else {
    if (!b->used) b->first_us = now;
    memcpy(b->data + b->used, row, len);  b->used += len;
    if (f1 < 0 && fer_mcf && b->used >= fer_mcf->block_size) f2 = fer_swap(now);
  }
  ngx_shmtx_unlock(&fer_shm->shpool->mutex);
  fer_post_flush(f1);  fer_post_flush(f2);
}

static void fer_tick(ngx_event_t * ev) {
  i64 now = fer_now();
  ngx_int_t flush = -1, reclaim = -1, i;
  fer_shbuf_t * b;
  if (!fer_shm || !fer_mcf) return;
  ngx_shmtx_lock(&fer_shm->shpool->mutex);
  b = &fer_shm->b[fer_shm->active];
  if (b->used && now - b->first_us >= (i64) fer_mcf->flush_interval * 1000) flush = fer_swap(now);
  /*  A flush whose worker died (kill -9, crash) is taken over.  */
  for (i = 0; i < 2 && flush < 0; i++) {
    b = &fer_shm->b[i];
    if (b->state == FER_BUF_FLUSHING && b->owner != ngx_pid
        && ((kill(b->owner, 0) == -1 && ngx_errno == NGX_ESRCH) || now - b->flush_start_us > FER_STALE_US)) {
      b->owner = ngx_pid;  b->flush_start_us = now;  reclaim = i;
      break;
    }
  }
  ngx_shmtx_unlock(&fer_shm->shpool->mutex);
  fer_post_flush(flush);
  if (reclaim >= 0) ngx_log_error(NGX_LOG_WARN, ev->log, 0, "ferret: taking over flush of an abandoned buffer");
  fer_post_flush(reclaim);
  if (!ngx_exiting && !ngx_terminate && !ngx_quit) ngx_add_timer(ev, MIN(fer_mcf->flush_interval, 10000));
}

static ngx_int_t fer_zone_init(ngx_shm_zone_t * zone, void * data) {
  fer_shm_t * sh = data;
  ngx_slab_pool_t * pool = (ngx_slab_pool_t *) zone->shm.addr;
  sz bs, page = (sz) ngx_pagesize - 1;
  if (sh) {
    zone->data = fer_shm = sh;
    if (sh->schema_hash != fer_schema_hash) {
      /*  Staged rows refer to columns by index and can no longer be decoded.  */
      ngx_log_error(NGX_LOG_WARN, zone->shm.log, 0, "ferret: schema changed, discarding %uz + %uz staged bytes",
                    sh->b[0].used, sh->b[1].used);
      sh->b[0].used = sh->b[1].used = 0;
      sh->b[0].state = sh->b[1].state = FER_BUF_IDLE;
      sh->b[sh->active].state = FER_BUF_FILL;
      sh->schema_hash = fer_schema_hash;
    }
    return NGX_OK;
  }
  if (!(sh = ngx_slab_alloc(pool, sizeof *sh))) return NGX_ERROR;
  memset(sh, 0, sizeof *sh);
  sh->magic = 0x50414e31;  sh->schema_hash = fer_schema_hash;  sh->shpool = pool;
  /*  Shrink the two buffers until both fit beside the slab bookkeeping.  */
  for (bs = (zone->shm.size / 2) & ~page;;) {
    bs = (bs - bs / 16) & ~page;
    if (bs < KiB(64)) {
      ngx_log_error(NGX_LOG_EMERG, zone->shm.log, 0, "ferret: shared memory zone too small");
      return NGX_ERROR;
    }
    if (!(sh->b[0].data = ngx_slab_alloc(pool, bs))) continue;
    if ((sh->b[1].data = ngx_slab_alloc(pool, bs))) break;
    ngx_slab_free(pool, sh->b[0].data);
  }
  sh->bufsize = bs;  sh->b[0].state = FER_BUF_FILL;
  sh->conn_seq = (ngx_atomic_uint_t) fer_now();
  pool->data = zone->data = fer_shm = sh;
  ngx_log_error(NGX_LOG_NOTICE, zone->shm.log, 0, "ferret: 2 x %uz byte staging buffers", bs);
  return NGX_OK;
}

/*  Enrichment.  */

static ngx_str_t fer_mmdb_str(MMDB_entry_s * e, ...) {
  MMDB_entry_data_s d;
  ngx_str_t s = ngx_null_string;
  va_list ap;
  int rc;
  va_start(ap, e);  rc = MMDB_vget_value(e, &d, ap);  va_end(ap);
  if (rc == MMDB_SUCCESS && d.has_data && d.type == MMDB_DATA_TYPE_UTF8_STRING) { s.data = (u_char *) d.utf8_string;  s.len = d.data_size; }
  return s;
}

static void fer_mmdb_e4(MMDB_entry_s * e, const char * key, i64 * out) {
  MMDB_entry_data_s d;
  if (MMDB_get_value(e, &d, "location", key, NULL) == MMDB_SUCCESS && d.has_data && d.type == MMDB_DATA_TYPE_DOUBLE)
    *out = (i64) (d.double_value * 10000.0);
}

static void fer_enrich(fer_conn_t * ctx, struct sockaddr * sa) {
  MMDB_lookup_result_s res;
  MMDB_entry_data_s d;
  int err;
#if (NGX_HAVE_INET6)
  struct sockaddr_in sin;
  if (sa->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *) sa)->sin6_addr)) {
    memset(&sin, 0, sizeof sin);  sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, &((struct sockaddr_in6 *) sa)->sin6_addr.s6_addr[12], 4);
    sa = (struct sockaddr *) &sin;
  }
#endif
  if (fer_geo_open) {
    res = MMDB_lookup_sockaddr(&fer_geo, sa, &err);
    if (err == MMDB_SUCCESS && res.found_entry) {
      ctx->geo_ok = 1;
      ctx->country = fer_mmdb_str(&res.entry, "country", "iso_code", NULL);
      ctx->region = fer_mmdb_str(&res.entry, "subdivisions", "0", "names", "en", NULL);
      ctx->city = fer_mmdb_str(&res.entry, "city", "names", "en", NULL);
      fer_mmdb_e4(&res.entry, "latitude", &ctx->lat_e4);
      fer_mmdb_e4(&res.entry, "longitude", &ctx->lon_e4);
    }
  }
  if (fer_asn_open) {
    res = MMDB_lookup_sockaddr(&fer_asn, sa, &err);
    if (err == MMDB_SUCCESS && res.found_entry) {
      if (MMDB_get_value(&res.entry, &d, "autonomous_system_number", NULL) == MMDB_SUCCESS && d.has_data) {
        if (d.type == MMDB_DATA_TYPE_UINT32) ctx->asn = d.uint32;
        else if (d.type == MMDB_DATA_TYPE_UINT16) ctx->asn = d.uint16;
      }
      ctx->asorg = fer_mmdb_str(&res.entry, "autonomous_system_organization", NULL);
    }
  }
  ctx->intel = fer_intel_ip(&fer_intel, ctx->caddr, ctx->caddr_len, &ctx->ipsum) | fer_intel_asn(&fer_intel, ctx->asn);
}

/*  Reverse DNS.  */

static void fer_rdns_fields(fer_rdns_t * job) {
  S(CC_RDNS_STATUS, job->status ? job->status : "timeout");
  if (job->name_len) B(CC_RDNS_NAME, job->name, job->name_len);
  if (job->fcrdns >= 0) N(CC_RDNS_FCRDNS, job->fcrdns);
  N(CC_RDNS_MS, ((job->end_us ? job->end_us : fer_now()) - job->start_us) / 1000);
}

static void fer_rdns_finish(fer_rdns_t * job, const char * status) {
  if (job->done) return;
  job->done = 1;  job->status = status;  job->end_us = fer_now();
  if (!job->closed) return;
  /*  The connection is gone: complete its parked row and free the job.  */
  if (job->row && fer_rb_reserve(&fer_rb, job->row_len) == 0) {
    memcpy(fer_rb.buf, job->row, job->row_len);
    fer_rb.len = job->row_len;  memcpy(&fer_rb.nfields, fer_rb.buf + 6, 2);  fer_rb.truncated = 0;
    fer_rdns_fields(job);
    fer_append(fer_rb.buf, fer_row_end(&fer_rb));
  }
  ngx_free(job->row);  ngx_free(job);
}

static void fer_rdns_fwd(ngx_resolver_ctx_t * ctx) {
  fer_rdns_t * job = ctx->data;
  ngx_uint_t i;
  u_char a[16];
  sz alen;
  if (ctx->state == NGX_OK) {
    job->fcrdns = 0;
    for (i = 0; i < ctx->naddrs && !job->fcrdns; i++) {
      fer_addr(ctx->addrs[i].sockaddr, a, &alen, NULL);
      job->fcrdns = alen == job->caddr_len && !memcmp(a, job->caddr, alen);
    }
  } else if (ctx->state == NGX_RESOLVE_NXDOMAIN) job->fcrdns = 0;
  job->ctx = NULL;
  ngx_resolve_name_done(ctx);
  fer_rdns_finish(job, job->status);
}

static void fer_rdns_ptr(ngx_resolver_ctx_t * ctx) {
  fer_rdns_t * job = ctx->data;
  ngx_resolver_ctx_t * f, temp;
  i64 left;
  switch (ctx->state) {
    case NGX_OK: job->status = "ok";  break;
    case NGX_RESOLVE_NXDOMAIN: job->status = "nxdomain";  break;
    case NGX_RESOLVE_TIMEDOUT: job->status = "timeout";  break;
    case NGX_RESOLVE_SERVFAIL: job->status = "servfail";  break;
    case NGX_RESOLVE_REFUSED: job->status = "refused";  break;
    case NGX_RESOLVE_FORMERR: job->status = "formerr";  break;
    case NGX_RESOLVE_NOTIMP: job->status = "notimp";  break;
    default: job->status = "error";
  }
  if (ctx->state == NGX_OK && ctx->name.len) {
    job->name_len = MIN(ctx->name.len, sizeof job->name);
    memcpy(job->name, ctx->name.data, job->name_len);
  }
  job->ctx = NULL;
  ngx_resolve_addr_done(ctx);
  left = (i64) job->budget - (fer_now() - job->start_us) / 1000;
  if (!job->name_len || left <= 0) { fer_rdns_finish(job, job->status);  return; }
  /*  Forward-confirm: does the name resolve back to the client address?  */
  memset(&temp, 0, sizeof temp);
  temp.name.data = job->name;  temp.name.len = job->name_len;
  f = ngx_resolve_start(job->resolver, &temp);
  if (!f || f == NGX_NO_RESOLVER || f->quick) {
    /*  A PTR that is an IP literal does not count as a hostname.  */
    if (f && f != NGX_NO_RESOLVER) job->fcrdns = 0;
    fer_rdns_finish(job, job->status);
    return;
  }
  f->name = temp.name;  f->handler = fer_rdns_fwd;  f->data = job;  f->timeout = (ngx_msec_t) left;
  job->ctx = f;
  if (ngx_resolve_name(f) != NGX_OK) {
    /*  The resolver has freed f.  */
    if (job->ctx == f) job->ctx = NULL;
    fer_rdns_finish(job, job->status);
  }
}

static void fer_rdns_start(fer_conn_t * ctx, ngx_connection_t * c) {
  fer_rdns_t * job;
  ngx_resolver_ctx_t * r;
  if (!fer_mcf->resolver || !ctx->caddr_len || !(job = ngx_calloc(sizeof *job, c->log))) return;
  job->resolver = fer_mcf->resolver;  job->budget = fer_mcf->rdns_timeout;
  job->start_us = fer_now();  job->fcrdns = -1;
  memcpy(job->caddr, ctx->caddr, ctx->caddr_len);  job->caddr_len = ctx->caddr_len;
  if (ctx->caddr_len == 4) {
    struct sockaddr_in * s4 = (struct sockaddr_in *) &job->sa;
    s4->sin_family = AF_INET;  memcpy(&s4->sin_addr, ctx->caddr, 4);  job->salen = sizeof *s4;
  }
#if (NGX_HAVE_INET6)
  else {
    struct sockaddr_in6 * s6 = (struct sockaddr_in6 *) &job->sa;
    s6->sin6_family = AF_INET6;  memcpy(&s6->sin6_addr, ctx->caddr, 16);  job->salen = sizeof *s6;
  }
#endif
  ctx->rdns = job;
  r = ngx_resolve_start(job->resolver, NULL);
  if (!r || r == NGX_NO_RESOLVER) { fer_rdns_finish(job, "error");  return; }
  r->addr.sockaddr = (struct sockaddr *) &job->sa;  r->addr.socklen = job->salen;
  r->handler = fer_rdns_ptr;  r->data = job;  r->timeout = job->budget;
  /*  On a resolver cache hit the handler runs right inside ngx_resolve_addr.  */
  job->ctx = r;
  if (ngx_resolve_addr(r) != NGX_OK) { job->ctx = NULL;  fer_rdns_finish(job, "error"); }
}

/*  Connections.  */

static const char * fer_close_class(fer_conn_t * ctx) {
  ngx_connection_t * c = ctx->c;
  unsigned timedout = c->timedout || (c->read && c->read->timedout);
  if (ctx->listen_tls && !ctx->hello_seen)
    return ctx->nreq ? "plain_http_on_tls" : timedout ? "timeout_no_hello" : "no_hello";
  if (ctx->hello_seen && !ctx->handshaked) return "tls_failed";
  if (!ctx->nreq) return timedout ? "timeout_no_request" : "no_request";
  switch (ctx->last_status) { case 400: case 408: case 413: case 414: case 494: case 497: return "http_error"; }
  if (timedout) return "idle_timeout";
  /*  nginx's HTTP/2 code sets c->error on any client EOF, clean or not.  */
  if (c->error && ctx->h2.is_h2 && (ctx->h2.goaway_seen ? !ctx->h2.goaway_code : ctx->h2.eof == 1))
    return "closed";
  return c->error ? "error" : "closed";
}

static void fer_conn_cleanup(void * data) {
  fer_conn_t * ctx = data;
  fer_syn_t * s = &ctx->syn;
  fer_hello_t * h = &ctx->hello;
  fer_rdns_t * job = ctx->rdns;
  sz n;
  if (fer_accepting == ctx) fer_accepting = NULL;
  fer_h2_finish(&ctx->h2);
  /*  An HTTP/2 connection counts all it carried, control frames included.  */
  if (ctx->h2.is_h2) { ctx->bytes_in = ctx->h2.bytes;  ctx->bytes_out = (u64) ctx->c->sent; }
  else if (!ctx->nreq) ctx->bytes_out += ctx->c->sent;
  fer_row_begin(&fer_rb, FER_TABLE_CONN);
  N(CC_TS, ctx->ts_accept);  N(CC_ID, ctx->id);  N(CC_WORKER, ngx_pid);  N(CC_LPORT, ctx->lport);
  B(CC_SADDR, ctx->saddr, ctx->saddr_len);  B(CC_CADDR, ctx->caddr, ctx->caddr_len);  N(CC_CPORT, ctx->cport);
  N(CC_SYN_MISSING, !ctx->syn_ok);
  if (ctx->syn_raw) B(CC_SYN_RAW, ctx->syn_raw, ctx->syn_len);
  if (ctx->syn_ok) {
    N(CC_SYN_TTL, s->ttl);  N(CC_SYN_DF, s->df);
    if (s->af == 4) N(CC_SYN_IPID, s->ipid);  else N(CC_SYN_FLOW, s->flowlabel);
    N(CC_SYN_TOS, s->tos);  N(CC_SYN_IPLEN, s->iplen);  N(CC_SYN_IPOPT, s->ipopt_len);
    N(CC_SYN_WIN, s->win);  N(CC_SYN_FLAGS, s->flags);  N(CC_SYN_MSS, s->mss);  N(CC_SYN_WS, s->wscale);
    B(CC_SYN_OPTS, s->opts, s->nopts);
    if (s->has_ts) { N(CC_SYN_TSVAL, s->tsval);  N(CC_SYN_TSECR, s->tsecr); }
    N(CC_SYN_PAYLOAD, s->payload_len);  N(CC_SYN_URG, s->urgptr);  N(CC_SYN_SEQ, s->seq);
    N(CC_SYN_ACKNZ, s->ack_nonzero);  S(CC_JA4T, s->ja4t);
  }
  if (TI_HAS(ctx->ti_len, rttvar)) {
    N(CC_TA_RTT, ctx->ti.rtt);  N(CC_TA_RTTVAR, ctx->ti.rttvar);
    N(CC_TA_SNDMSS, ctx->ti.snd_mss);  N(CC_TA_RCVMSS, ctx->ti.rcv_mss);  N(CC_TA_ADVMSS, ctx->ti.advmss);
    N(CC_TA_OPTS, ctx->ti.options);  N(CC_TA_SWS, ctx->ti.wscale & 15);  N(CC_TA_RWS, ctx->ti.wscale >> 4);
  }
  if (ctx->th_ok) { N(CC_TH_RTT, ctx->th_rtt);  N(CC_TH_RETR, ctx->th_retr); }
  N(CC_TLS, ctx->listen_tls);
  if (ctx->hello_seen) {
    N(CC_TS_HELLO, ctx->ts_hello);  N(CC_H_LEGACY, ctx->hello_legacy);
    B(CC_H_CIPHERS, ctx->h_ciphers, ctx->h_ciphers_len);  B(CC_H_EXTS, ctx->h_exts, ctx->h_exts_len);
    B(CC_H_COMP, ctx->h_comp, ctx->h_comp_len);  N(CC_H_SIDLEN, ctx->h_sid_len);
    S(CC_SNI, h->sni);  S(CC_ALPN, h->alpn);
    B(CC_VERSIONS, h->versions, h->versions_len);  B(CC_GROUPS, h->groups, h->groups_len);
    B(CC_SIGALGS, h->sigalgs, h->sigalgs_len);  B(CC_KEYSHARE, h->keyshare, h->keyshare_len);
    N(CC_GREASE, h->grease);  S(CC_JA4, h->ja4);  S(CC_JA4R, h->ja4_r);  S(CC_JA3, h->ja3);  S(CC_JA3H, h->ja3_hash);
  }
  if (ctx->handshaked) {
    N(CC_TS_HS, ctx->ts_hs);  V(CC_TLS_VER, &ctx->tls_ver);  V(CC_TLS_CIPHER, &ctx->tls_cipher);
    V(CC_TLS_GROUP, &ctx->tls_group);  V(CC_TLS_ALPN, &ctx->tls_alpn);  N(CC_TLS_REUSED, ctx->reused);
  }
  if (ctx->alert_sent) N(CC_ALERT_SENT, ctx->alert_sent);
  if (ctx->alert_recv) N(CC_ALERT_RECV, ctx->alert_recv);
  N(CC_TS_CLOSE, fer_now());  N(CC_NREQ, ctx->nreq);
  N(CC_BYTES_IN, ctx->bytes_in);  N(CC_BYTES_OUT, ctx->bytes_out);
  S(CC_CLOSE, fer_close_class(ctx));
  if (ctx->nreq) N(CC_LAST_STATUS, ctx->last_status);
  if (ctx->geo_ok) {
    V(CC_COUNTRY, &ctx->country);  V(CC_REGION, &ctx->region);  V(CC_CITY, &ctx->city);
    N(CC_LAT, ctx->lat_e4);  N(CC_LON, ctx->lon_e4);
  }
  if (ctx->asn) { N(CC_ASN, ctx->asn);  V(CC_ASORG, &ctx->asorg); }
  if (fer_intel.map) { N(CC_INTEL, ctx->intel);  N(CC_IPSUM, ctx->ipsum);  N(CC_INTEL_VER, fer_intel.version); }
  if (ctx->h2.is_h2) {
    fer_h2_t * h2 = &ctx->h2;
    char fp[sizeof h2->settings + sizeof h2->prio + sizeof h2->pseudo + 16];
    unsigned i;
    N(CC_H2, 1);
    if (h2->settings_seen) S(CC_H2_SETTINGS, h2->settings);
    if (h2->wu_seen) N(CC_H2_WU, h2->wu);
    if (h2->prio[0]) S(CC_H2_PRIO, h2->prio);
    if (h2->pseudo[0]) S(CC_H2_PSEUDO, h2->pseudo);
    if (h2->hprio_seen) S(CC_H2_HPRIO, h2->hprio);
    fer_h2_fp(h2, fp, sizeof fp);  S(CC_H2_FP, fp);
    Fi(FER_H2_NTYPES, N(CC_H2_DATA + i, h2->frames[i]));
    N(CC_H2_MAXSID, h2->max_sid);
    if (h2->goaway_seen) N(CC_H2_GOAWAY_ERR, h2->goaway_code);
  }
  fer_hello_free(h);
  if (!job || job->done) {
    if (job) fer_rdns_fields(job);
    fer_append(fer_rb.buf, fer_row_end(&fer_rb));
    ngx_free(job);
    return;
  }
  /*  DNS is still running: park the row for the resolver handler to write.  */
  n = fer_row_end(&fer_rb);
  if (n && (job->row = ngx_alloc(n, ngx_cycle->log))) { memcpy(job->row, fer_rb.buf, n);  job->row_len = n; }
  job->closed = 1;
}

static fer_conn_t * fer_find_conn(ngx_connection_t * c) {
  ngx_pool_cleanup_t * cln;
  if (!c || !c->pool) return NULL;
  for (cln = c->pool->cleanup; cln; cln = cln->next)
    if (cln->handler == fer_conn_cleanup) return cln->data;
  return NULL;
}

static void fer_init_connection(ngx_connection_t * c) {
  fer_conn_t * ctx;
  ngx_pool_cleanup_t * cln;
  u_char syn[512];
  socklen_t sl = sizeof syn;
  if (!fer_mcf || !fer_mcf->active || !(ctx = ngx_pcalloc(c->pool, sizeof *ctx))
      || !(cln = ngx_pool_cleanup_add(c->pool, 0))) { fer_orig_handler(c);  return; }
  cln->handler = fer_conn_cleanup;  cln->data = ctx;
  ctx->c = c;  ctx->ts_accept = fer_now();
  ctx->id = fer_shm ? (u64) ngx_atomic_fetch_add(&fer_shm->conn_seq, 1) : 0;
  fer_addr(c->sockaddr, ctx->caddr, &ctx->caddr_len, &ctx->cport);
  if (ngx_connection_local_sockaddr(c, NULL, 0) == NGX_OK) fer_addr(c->local_sockaddr, ctx->saddr, &ctx->saddr_len, &ctx->lport);
  if (c->type == SOCK_STREAM && c->sockaddr->sa_family != AF_UNIX) {
    if (fer_mcf->save_syn && getsockopt(c->fd, IPPROTO_TCP, TCP_SAVED_SYN, syn, &sl) == 0 && sl > 0) {
      if ((ctx->syn_raw = ngx_pnalloc(c->pool, sl))) { memcpy(ctx->syn_raw, syn, sl);  ctx->syn_len = sl; }
      ctx->syn_ok = fer_syn_parse(syn, sl, &ctx->syn) == 0;
    }
    fer_tcp_info(c->fd, &ctx->ti, &ctx->ti_len);
  }
  fer_enrich(ctx, c->sockaddr);
  if (fer_mcf->rdns) fer_rdns_start(ctx, c);
  /*  Watch for an HTTP/2 preface in cleartext.  TLS reads bypass c->recv
      until the handshake is done; fer_info_cb takes over from there.  */
  if (c->type == SOCK_STREAM && c->recv == ngx_recv) c->recv = fer_recv_plain;
  fer_accepting = ctx;
  fer_orig_handler(c);
  /*  The handler may already have processed and closed the connection, in
      which case the cleanup has reset fer_accepting.  */
#if (NGX_HTTP_SSL)
  if (fer_accepting == ctx) {
    ngx_http_connection_t * hc = c->data;
    if (hc && hc->addr_conf && hc->addr_conf->ssl) ctx->listen_tls = 1;
  }
#endif
  fer_accepting = NULL;
}

/*  TLS.  */

#if (NGX_HTTP_SSL)

static fer_conn_t * fer_ssl_conn(const SSL * ssl) {
  fer_conn_t * ctx = SSL_get_ex_data(ssl, fer_ssl_idx);
  if (!ctx && (ctx = fer_find_conn(ngx_ssl_get_connection((SSL *) ssl)))) SSL_set_ex_data((SSL *) ssl, fer_ssl_idx, ctx);
  return ctx;
}

static u_char * fer_pdup(ngx_pool_t * pool, const void * p, sz n) {
  u_char * d = ngx_pnalloc(pool, n ? n : 1);
  if (d && n) memcpy(d, p, n);
  return d;
}

static void fer_parse_hello(fer_conn_t * ctx, const u_char * m, sz len) {
  const u_char * p = m + 4 + 2 + 32, * end = m + len;
  fer_hello_in_t in;
  ngx_pool_t * pool = ctx->c->pool;
  sz n;
  /*  Handshake header (type, u24 length), version, random, session id.  */
  if (len < 4 + 2 + 32 + 1) return;
  memset(&in, 0, sizeof in);
  in.legacy_version = rd16be(m + 4);
  n = *p++;
  if (p + n > end) return;
  ctx->h_sid_len = n;  p += n;
  if (p + 2 > end) return;
  n = rd16be(p);  p += 2;
  if (p + n > end) return;
  in.ciphers = p;  in.ciphers_len = n;  p += n;
  if (p + 1 > end) return;
  n = *p++;
  if (p + n > end) return;
  ctx->h_comp = fer_pdup(pool, p, n);  ctx->h_comp_len = n;  p += n;
  if (p + 2 <= end) {
    n = rd16be(p);  p += 2;
    in.exts = p;  in.exts_len = MIN(n, (sz) (end - p));
    ctx->h_exts = fer_pdup(pool, in.exts, in.exts_len);  ctx->h_exts_len = in.exts_len;
  }
  ctx->hello_legacy = in.legacy_version;
  ctx->h_ciphers = fer_pdup(pool, in.ciphers, in.ciphers_len);  ctx->h_ciphers_len = in.ciphers_len;
  fer_hello_parse(&in, &ctx->hello);
  ctx->hello_seen = 1;
}

static void fer_msg_cb(int write_p, int version, int type, const void * buf, sz len, SSL * ssl, void * arg) {
  fer_conn_t * ctx;
  const u_char * m = buf;
  fer_tcp_info_t ti;
  socklen_t tl;
  if ((type != SSL3_RT_HANDSHAKE && type != SSL3_RT_ALERT) || !(ctx = fer_ssl_conn(ssl))) return;
  if (type == SSL3_RT_ALERT) {
    ngx_uint_t * a = write_p ? &ctx->alert_sent : &ctx->alert_recv;
    if (len >= 2 && !*a) *a = rd16be(m);
    return;
  }
  if (write_p || len < 1 || m[0] != SSL3_MT_CLIENT_HELLO || ctx->hello_seen) return;
  ctx->ts_hello = fer_now();
  fer_tcp_info(ctx->c->fd, &ti, &tl);
  if (TI_HAS(tl, total_retrans)) { ctx->th_rtt = ti.rtt;  ctx->th_retr = ti.total_retrans;  ctx->th_ok = 1; }
  fer_parse_hello(ctx, m, len);
}

static ssize_t fer_recv_tls(ngx_connection_t * c, u_char * buf, size_t size) {
  ssize_t n = ngx_ssl_recv(c, buf, size);
  fer_conn_t * ctx;
  if (n >= 0 && c->ssl && (ctx = fer_ssl_conn(c->ssl->connection)) && ctx->c == c) {
    if (!n) fer_h2_eof(&ctx->h2);
    else if (fer_h2_feed(&ctx->h2, buf, (sz) n) < 0) c->recv = ngx_ssl_recv;
  }
  return n;
}

static void fer_ssl_handshaked(ngx_connection_t * c) {
  fer_conn_t * ctx = fer_ssl_conn(c->ssl->connection);
  if (!ctx || !ctx->ssl_handler) return;       /*  Cannot happen.  */
  c->ssl->handler = ctx->ssl_handler;  ctx->ssl_handler = NULL;
  if (c->ssl->handshaked && c->recv == ngx_ssl_recv) c->recv = fer_recv_tls;
  c->ssl->handler(c);
}

static void fer_h2_watch_tls(fer_conn_t * ctx) {
  ngx_connection_t * c = ctx->c;
  memset(&ctx->h2, 0, sizeof ctx->h2);
  if (c->recv == ngx_ssl_recv) c->recv = fer_recv_tls;
  else if (c->ssl->handler && c->ssl->handler != fer_ssl_handshaked) {
    ctx->ssl_handler = c->ssl->handler;  c->ssl->handler = fer_ssl_handshaked;
  }
}

static void fer_set_str(fer_conn_t * ctx, ngx_str_t * f, const char * s) {
  if (!s) return;
  f->len = strlen(s);
  if (!(f->data = fer_pdup(ctx->c->pool, s, f->len))) f->len = 0;
}

static void fer_info_cb(const SSL * ssl, int where, int ret) {
  fer_conn_t * ctx;
  const SSL_CIPHER * cipher;
  const unsigned char * alpn;
  unsigned alpnlen;
  if (fer_orig_info_cb) fer_orig_info_cb(ssl, where, ret);
  if (!(where & SSL_CB_HANDSHAKE_DONE) || !(ctx = fer_ssl_conn(ssl)) || ctx->handshaked) return;
  ctx->handshaked = 1;  ctx->ts_hs = fer_now();
  ctx->reused = SSL_session_reused((SSL *) ssl) ? 1 : 0;
  fer_set_str(ctx, &ctx->tls_ver, SSL_get_version(ssl));
  if ((cipher = SSL_get_current_cipher(ssl))) fer_set_str(ctx, &ctx->tls_cipher, SSL_CIPHER_get_name(cipher));
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
  fer_set_str(ctx, &ctx->tls_group, SSL_get0_group_name((SSL *) ssl));
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
  {
    int nid = SSL_get_negotiated_group((SSL *) ssl);
    if (nid > 0) fer_set_str(ctx, &ctx->tls_group, SSL_group_to_name((SSL *) ssl, nid));
  }
#endif
  SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
  if (alpn && alpnlen && (ctx->tls_alpn.data = fer_pdup(ctx->c->pool, alpn, alpnlen))) ctx->tls_alpn.len = alpnlen;
  if (alpnlen == 2 && !memcmp(alpn, "h2", 2)) fer_h2_watch_tls(ctx);
}

static ngx_int_t fer_install_ssl(ngx_conf_t * cf) {
  ngx_http_core_main_conf_t * cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  ngx_http_core_srv_conf_t ** cscf = cmcf->servers.elts;
  ngx_http_ssl_srv_conf_t * sscf;
  ngx_uint_t i;
  void (*cb)(const SSL *, int, int);
  if (fer_ssl_idx == -1 && (fer_ssl_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL)) == -1) return NGX_ERROR;
  Fi(cmcf->servers.nelts,
    sscf = cscf[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
    if (!sscf || !sscf->ssl.ctx) continue;
    SSL_CTX_set_msg_callback(sscf->ssl.ctx, fer_msg_cb);
    cb = SSL_CTX_get_info_callback(sscf->ssl.ctx);
    if (cb == fer_info_cb) continue;
    if (cb && fer_orig_info_cb && fer_orig_info_cb != cb)
      ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "ferret: SSL contexts use different info callbacks, chaining the first one");
    else if (cb) fer_orig_info_cb = cb;
    SSL_CTX_set_info_callback(sscf->ssl.ctx, fer_info_cb));
  return NGX_OK;
}

#endif

static ssize_t fer_recv_plain(ngx_connection_t * c, u_char * buf, size_t size) {
  ssize_t n = ngx_recv(c, buf, size);
  fer_conn_t * ctx;
  if (n >= 0 && (ctx = fer_find_conn(c)) && ctx->c == c) {
    if (!n) fer_h2_eof(&ctx->h2);
    else if (fer_h2_feed(&ctx->h2, buf, (sz) n) < 0) c->recv = ngx_recv;
  }
  return n;
}

/*  Requests.  */

#define H(n, c) { n, sizeof(n) - 1, c }
static const struct { const char * name;  sz len;  unsigned col; } fer_hdr_map[] = {
  H("user-agent", RC_H_UA), H("accept", RC_H_ACCEPT), H("accept-language", RC_H_ALANG),
  H("accept-encoding", RC_H_AENC), H("referer", RC_H_REFERER), H("origin", RC_H_ORIGIN),
  H("connection", RC_H_CONNECTION), H("cache-control", RC_H_CACHECTL), H("pragma", RC_H_PRAGMA),
  H("upgrade", RC_H_UPGRADE), H("content-type", RC_H_CTYPE), H("content-length", RC_H_CLEN),
  H("transfer-encoding", RC_H_TE), H("x-requested-with", RC_H_XRW), H("dnt", RC_H_DNT),
  H("sec-gpc", RC_H_GPC), H("sec-fetch-site", RC_H_SFSITE), H("sec-fetch-mode", RC_H_SFMODE),
  H("sec-fetch-dest", RC_H_SFDEST), H("sec-fetch-user", RC_H_SFUSER), H("sec-ch-ua", RC_H_CHUA),
  H("sec-ch-ua-mobile", RC_H_CHMOB), H("sec-ch-ua-platform", RC_H_CHPLAT), H("priority", RC_H_PRIORITY),
  H("upgrade-insecure-requests", RC_H_UIR), H("x-forwarded-for", RC_H_XFF), H("x-real-ip", RC_H_XRIP),
  H("forwarded", RC_H_FORWARDED), H("via", RC_H_VIA), H("te", RC_H_TEH), H("range", RC_H_RANGE),
  H("if-none-match", RC_H_INM), H("if-modified-since", RC_H_IMS), H("expect", RC_H_EXPECT),
};
#undef H
#define FER_NHDR ARRAY_LEN(fer_hdr_map)

/*  The time the request headers were read, kept as the request's ctx.  */
static ngx_int_t fer_post_read_handler(ngx_http_request_t * r) {
  i64 * ts;
  if (r != r->main || ngx_http_get_module_ctx(r, ngx_http_ferret_module)) return NGX_DECLINED;
  if ((ts = ngx_palloc(r->pool, sizeof *ts))) { *ts = fer_now();  ngx_http_set_ctx(r, ts, ngx_http_ferret_module); }
  return NGX_DECLINED;
}

/*  Append a piece to a newline-joined list of at most cap bytes.  */
static void fer_acc(ngx_pool_t * pool, ngx_str_t * acc, u_char * p, sz n, sz cap) {
  u_char * d;
  if (acc->len >= cap) return;
  n = MIN(n, cap - acc->len);
  if (!acc->data) { acc->data = p;  acc->len = n;  return; }
  if (!(d = ngx_pnalloc(pool, acc->len + 1 + n))) return;
  memcpy(d, acc->data, acc->len);  d[acc->len] = '\n';  memcpy(d + acc->len + 1, p, n);
  acc->data = d;  acc->len += 1 + n;
}

static void fer_auth(fer_main_conf_t * mcf, ngx_str_t * v) {
  u_char * p = v->data, * end = p + v->len, * sp, * o, * oe;
  u8 hash[8];
  if (!(sp = ngx_strlchr(p, end, ' '))) sp = end;
  C(RC_AUTH_SCHEME, p, (sz) (sp - p), 64);
  if (sp - p == 8 && !ngx_strncasecmp(p, (u_char *) "X-Matrix", 8)) {
    if (!(o = ngx_strlcasestrn(sp, end, (u_char *) "origin=", 6))) return;
    o += 7;
    if (o < end && *o == '"') { o++;  if (!(oe = ngx_strlchr(o, end, '"'))) oe = end; }
    else for (oe = o; oe < end && *oe != ',' && *oe != ' '; oe++);
    C(RC_XMATRIX, o, (sz) (oe - o), 255);
    return;
  }
  while (sp < end && *sp == ' ') sp++;
  if (mcf->hash_key.len && sp < end) {
    fer_khash(mcf->hash_key.data, mcf->hash_key.len, sp, (sz) (end - sp), hash);
    B(RC_AUTH_HASH, hash, 8);
  }
}

/*  Cookie names in clear, values only as keyed hashes, at most 64 of them.  */
static void fer_cookies(ngx_pool_t * pool, fer_main_conf_t * mcf, ngx_str_t * v, ngx_str_t * names, ngx_str_t * hashes) {
  u_char * p = v->data, * end = p + v->len, * ns, * ne, * vs, * d;
  for (;;) {
    while (p < end && (*p == ' ' || *p == ';')) p++;
    if (p == end) return;
    for (ns = p; p < end && *p != '=' && *p != ';'; p++);
    ne = vs = p;
    if (p < end && *p == '=') for (vs = ++p; p < end && *p != ';'; p++);
    while (ne > ns && ne[-1] == ' ') ne--;
    fer_acc(pool, names, ns, (sz) (ne - ns), FER_VAL_MAX);
    if (mcf->hash_key.len && hashes->len < 64 * 8 && (d = ngx_pnalloc(pool, hashes->len + 8))) {
      if (hashes->len) memcpy(d, hashes->data, hashes->len);
      fer_khash(mcf->hash_key.data, mcf->hash_key.len, vs, (sz) (p - vs), d + hashes->len);
      hashes->data = d;  hashes->len += 8;
    }
  }
}

static i64 fer_ms(ngx_msec_t v) { return v == (ngx_msec_t) -1 ? -1 : (i64) v; }

static ngx_int_t fer_log_handler(ngx_http_request_t * r) {
  fer_main_conf_t * mcf = ngx_http_get_module_main_conf(r, ngx_http_ferret_module);
  fer_loc_conf_t * lcf = ngx_http_get_module_loc_conf(r, ngx_http_ferret_module);
  ngx_connection_t * c = r->connection;
  ngx_http_core_srv_conf_t * cscf;
  fer_conn_t * ctx;
  i64 * ts_hdr, ts, ts_end;
  ngx_list_part_t * part;
  ngx_table_elt_t * h;
  ngx_uint_t i, k, nh = 0, status, setck = 0, dup = 0;
  ngx_str_t vals[FER_NHDR], names = ngx_null_string, extra = ngx_null_string, cnames = ngx_null_string,
            chashes = ngx_null_string, tag, * rl = &r->request_line, * t, * ch;
  sz hbytes = 0, ml = r->method_name.len, ul = r->unparsed_uri.len;
  u_char * q, * e, * uri = r->unparsed_uri.data, * uend = uri + ul;
  fer_tcp_info_t ti;
  socklen_t tl;
  if (!mcf->active || !lcf->enable || !fer_shm) return NGX_OK;
  ctx = fer_find_conn(c);
  ts_hdr = ngx_http_get_module_ctx(r, ngx_http_ferret_module);
  ts = (i64) r->start_sec * 1000000 + (i64) r->start_msec * 1000;
  ts_end = fer_now();
  status = r->err_status ? r->err_status : r->headers_out.status ? r->headers_out.status
         : r->http_version == NGX_HTTP_VERSION_9 ? 9 : 0;
  fer_row_begin(&fer_rb, FER_TABLE_REQ);
  N(RC_TS, ts);
  if (ctx) {
    N(RC_CONN, ctx->id);  N(RC_SEQ, ctx->nreq);
    if (ctx->nreq) N(RC_GAP, ts - ctx->prev_end);
  }
  if (ts_hdr) N(RC_TS_HDR, *ts_hdr);
  N(RC_TS_END, ts_end);  N(RC_DUR, ts_end - ts);

  /*  The request line is kept only when it is not just method, uri and protocol.  */
  V(RC_METHOD, &r->method_name);
  if (uri && ul) {
    q = ngx_strlchr(uri, uend, '?');
    C(RC_PATH, uri, (sz) ((q ? q : uend) - uri), FER_LINE_MAX);
    if (q && q + 1 < uend) Q(RC_ARGS, q + 1, (sz) (uend - q - 1), 1);
  }
  V(RC_PROTO, &r->http_protocol);
  if (!(rl->len && rl->len == ml + 1 + ul + 1 + r->http_protocol.len && r->http_protocol.len
        && !ngx_strncmp(rl->data, r->method_name.data, ml) && rl->data[ml] == ' '
        && !ngx_strncmp(rl->data + ml + 1, uri, ul) && rl->data[ml + 1 + ul] == ' ')) {
    if (rl->len) Q(RC_RLINE, rl->data, MIN(rl->len, FER_LINE_MAX), 0);
    else if (r->request_start && r->header_in && r->request_start >= r->header_in->start && r->request_start < r->header_in->last) {
      /*  An unparsable request: keep what the client sent.  */
      for (e = r->request_start; e < r->header_in->last && *e != '\n' && (sz) (e - r->request_start) < FER_LINE_MAX; e++);
      Q(RC_RLINE, r->request_start, (sz) (e - r->request_start), 0);
    }
  }
  if (r->headers_in.host) C(RC_HOST, r->headers_in.host->value.data, r->headers_in.host->value.len, 255);
  if ((cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module))) V(RC_SERVER, &cscf->server_name);
  if (ctx && ctx->hello.sni && r->headers_in.server.len) {
    sz sl = strlen(ctx->hello.sni);
    N(RC_SNI_MISMATCH, !(sl == r->headers_in.server.len && !ngx_strncasecmp((u_char *) ctx->hello.sni, r->headers_in.server.data, sl)));
  }

  memset(vals, 0, sizeof vals);
  for (part = &r->headers_in.headers.part; part; part = part->next)
    for (h = part->elts, i = 0; i < part->nelts; i++) {
      nh++;  hbytes += h[i].key.len + 2 + h[i].value.len + 2;
      fer_acc(r->pool, &names, h[i].key.data, h[i].key.len, FER_LINE_MAX);
      if (h[i].next) dup = 1;
      for (k = 0; k < FER_NHDR; k++)
        if (fer_hdr_map[k].len == h[i].key.len && !ngx_strncmp(fer_hdr_map[k].name, h[i].lowcase_key, h[i].key.len)) {
          if (vals[k].data) dup = 1;
          fer_acc(r->pool, &vals[k], h[i].value.data, h[i].value.len, FER_VAL_MAX);
          break;
        }
      if (k < FER_NHDR) continue;
      if (h[i].key.len == 13 && !ngx_strncmp(h[i].lowcase_key, "authorization", 13)) fer_auth(mcf, &h[i].value);
      else if (h[i].key.len == 6 && !ngx_strncmp(h[i].lowcase_key, "cookie", 6)) fer_cookies(r->pool, mcf, &h[i].value, &cnames, &chashes);
      else if (mcf->capture_headers)
        for (ch = mcf->capture_headers->elts, k = 0; k < mcf->capture_headers->nelts; k++) {
          if (ch[k].len != h[i].key.len || ngx_strncmp(ch[k].data, h[i].lowcase_key, ch[k].len)) continue;
          if ((e = ngx_pnalloc(r->pool, h[i].key.len + 2 + h[i].value.len))) {
            q = ngx_cpymem(e, h[i].key.data, h[i].key.len);  *q++ = ':';  *q++ = ' ';
            q = ngx_cpymem(q, h[i].value.data, h[i].value.len);
            fer_acc(r->pool, &extra, e, (sz) (q - e), FER_LINE_MAX);
          }
          break;
        }
    }
  /*  nginx links repeats of only some well-known headers through h->next;
      look for repeated names, case-insensitively, among all of them too.  */
  if (!dup && nh > 1 && names.data) {
    u_char * a, * ae, * b, * be, * end = names.data + names.len;
    for (a = names.data; a < end && !dup; a = ae + 1) {
      if (!(ae = ngx_strlchr(a, end, '\n'))) ae = end;
      for (b = ae + 1; b < end && !dup; b = be + 1) {
        if (!(be = ngx_strlchr(b, end, '\n'))) be = end;
        dup = be - b == ae - a && !ngx_strncasecmp(a, b, (sz) (ae - a));
      }
    }
  }
  V(RC_HNAMES, &names);  N(RC_HCOUNT, nh);  N(RC_HBYTES, hbytes);  N(RC_HDUP, dup);
  for (k = 0; k < FER_NHDR; k++) {
    if (!vals[k].data) continue;
    if (fer_hdr_map[k].col == RC_H_REFERER) Q(RC_H_REFERER, vals[k].data, vals[k].len, 0);
    else B(fer_hdr_map[k].col, vals[k].data, vals[k].len);
  }
  V(RC_H_EXTRA, &extra);  V(RC_COOKIE_NAMES, &cnames);  V(RC_COOKIE_HASHES, &chashes);

  N(RC_REQ_LEN, r->request_length);  N(RC_STATUS, status);  N(RC_BYTES_SENT, c->sent);
  N(RC_BODY_SENT, c->sent > (off_t) r->header_size ? c->sent - (off_t) r->header_size : 0);
  V(RC_RESP_CTYPE, &r->headers_out.content_type);
  if (r->headers_out.location && r->headers_out.location->hash)
    Q(RC_RESP_LOC, r->headers_out.location->value.data, r->headers_out.location->value.len, 0);
  for (part = &r->headers_out.headers.part; part; part = part->next)
    for (h = part->elts, i = 0; i < part->nelts; i++)
      setck += h[i].hash && h[i].key.len == 10 && !ngx_strncasecmp(h[i].key.data, (u_char *) "set-cookie", 10);
  N(RC_RESP_SETCK, setck);  N(RC_KEEPALIVE, r->keepalive);

  if (r->upstream_states && r->upstream_states->nelts) {
    ngx_http_upstream_state_t * u = (ngx_http_upstream_state_t *) r->upstream_states->elts + r->upstream_states->nelts - 1;
    if (u->peer) V(RC_UP_ADDR, u->peer);
    N(RC_UP_STATUS, u->status);  N(RC_UP_CONNECT, fer_ms(u->connect_time));
    N(RC_UP_HEADER, fer_ms(u->header_time));  N(RC_UP_RESPONSE, fer_ms(u->response_time));
    N(RC_UP_TRIES, r->upstream_states->nelts);  N(RC_UP_BIN, u->bytes_received);  N(RC_UP_BOUT, u->bytes_sent);
  }
  if (c->fd != (ngx_socket_t) -1 && c->type == SOCK_STREAM && c->sockaddr->sa_family != AF_UNIX) {
    fer_tcp_info(c->fd, &ti, &tl);
    if (TI_HAS(tl, total_retrans)) { N(RC_T_RTT, ti.rtt);  N(RC_T_RTTVAR, ti.rttvar);  N(RC_T_RETRANS, ti.total_retrans);  N(RC_T_CWND, ti.snd_cwnd); }
    if (TI_HAS(tl, bytes_received)) { N(RC_T_ACKED, ti.bytes_acked);  N(RC_T_RECV, ti.bytes_received); }
    if (TI_HAS(tl, min_rtt)) N(RC_T_MINRTT, ti.min_rtt);
    if (TI_HAS(tl, delivery_rate)) N(RC_T_RATE, ti.delivery_rate);
  }
  if (lcf->traps && uri)
    for (t = lcf->traps->elts, k = 0; k < lcf->traps->nelts; k++)
      if (ul >= t[k].len && !ngx_strncmp(uri, t[k].data, t[k].len)) { N(RC_TRAP, 1);  break; }
  if (lcf->tag && ngx_http_complex_value(r, lcf->tag, &tag) == NGX_OK) C(RC_TAG, tag.data, tag.len, 255);
#if (NGX_HTTP_V2)
  /*  A stream that depends on no other has the parent (void *) -1.  */
  if (r->stream && r->stream->node) {
    ngx_http_v2_node_t * nd = r->stream->node;
    N(RC_H2_STREAM, nd->id);  N(RC_H2_WEIGHT, nd->weight);
    if (nd->parent && nd->parent != (void *) -1) N(RC_H2_PARENT, nd->parent->id);
  }
#endif
  fer_append(fer_rb.buf, fer_row_end(&fer_rb));
  if (ctx) {
    ctx->nreq++;  ctx->prev_end = ts_end;
    ctx->bytes_in += (u64) r->request_length;  ctx->bytes_out += (u64) c->sent;
    ctx->last_status = status;
  }
  return NGX_OK;
}

/*  Configuration.  */

static ngx_int_t fer_preconfiguration(ngx_conf_t * cf) {
  u32 h = 2166136261u;
  unsigned t, i;
  const char * p;
  for (t = 1; t < 3; t++)
    Fi(fer_tables[t].ncols,
      for (p = fer_tables[t].cols[i].name; *p; p++) h = (h ^ (u8) *p) * 16777619u;
      h = (h ^ fer_tables[t].cols[i].type) * 16777619u);
  fer_schema_hash = h;
  return NGX_OK;
}

static void * fer_create_main_conf(ngx_conf_t * cf) {
  fer_main_conf_t * mcf = ngx_pcalloc(cf->pool, sizeof *mcf);
  if (!mcf) return NULL;
  mcf->block_size = NGX_CONF_UNSET_SIZE;  mcf->flush_interval = NGX_CONF_UNSET_MSEC;
  mcf->preset = (u32) -1;  mcf->retention = NGX_CONF_UNSET;
  mcf->save_syn = NGX_CONF_UNSET;  mcf->rdns = NGX_CONF_UNSET;  mcf->rdns_timeout = NGX_CONF_UNSET_MSEC;
  return mcf;
}

static char * fer_read_key(ngx_conf_t * cf, fer_main_conf_t * mcf) {
  ngx_file_t file;
  ngx_file_info_t fi;
  ssize_t n = -1;
  sz size;
  u_char * p;
  if (ngx_conf_full_name(cf->cycle, &mcf->hash_key_file, 1) != NGX_OK) return NGX_CONF_ERROR;
  memset(&file, 0, sizeof file);
  file.name = mcf->hash_key_file;  file.log = cf->log;
  file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
  if (file.fd == NGX_INVALID_FILE) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_open_file_n " \"%V\" failed", &file.name);
    return NGX_CONF_ERROR;
  }
  if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR || ngx_file_size(&fi) < 16 || ngx_file_size(&fi) > 4096) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ferret_hash_key \"%V\" must be 16..4096 bytes", &file.name);
    ngx_close_file(file.fd);
    return NGX_CONF_ERROR;
  }
  size = (sz) ngx_file_size(&fi);
  if ((p = ngx_pnalloc(cf->pool, size))) n = ngx_read_file(&file, p, size, 0);
  ngx_close_file(file.fd);
  if (n != (ssize_t) size) return NGX_CONF_ERROR;
  mcf->hash_key.data = p;  mcf->hash_key.len = size;
  return NGX_CONF_OK;
}

static char * fer_init_main_conf(ngx_conf_t * cf, void * conf) {
  fer_main_conf_t * mcf = conf;
  ngx_str_t name = ngx_string("ferret"), * dbs[] = { &mcf->geo_db, &mcf->asn_db, &mcf->intel_db };
  ngx_uint_t i;
  ngx_conf_init_size_value(mcf->block_size, MiB(8));
  ngx_conf_init_msec_value(mcf->flush_interval, 10 * 60 * 1000);
  ngx_conf_init_value(mcf->retention, -1);
  ngx_conf_init_value(mcf->save_syn, 1);
  ngx_conf_init_value(mcf->rdns, 0);
  ngx_conf_init_msec_value(mcf->rdns_timeout, 1000);
  if (mcf->preset == (u32) -1) mcf->preset = 6;
  if (!mcf->dir.len) return NGX_CONF_OK;
  mcf->active = 1;
  while (mcf->dir.len > 1 && mcf->dir.data[mcf->dir.len - 1] == '/') mcf->dir.len--;
  if (ngx_conf_full_name(cf->cycle, &mcf->dir, 0) != NGX_OK) return NGX_CONF_ERROR;
  if (!mcf->zone) {
    if (!(mcf->zone = ngx_shared_memory_add(cf, &name, MiB(64), &ngx_http_ferret_module))) return NGX_CONF_ERROR;
    mcf->zone->init = fer_zone_init;
  }
  if (mcf->block_size > mcf->zone->shm.size / 3) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ferret_block_size %uz is too large for a %uz byte zone (max zone/3)",
                       mcf->block_size, mcf->zone->shm.size);
    return NGX_CONF_ERROR;
  }
#if (NGX_THREADS)
  if (!mcf->thread_pool) {
    ngx_str_t def = ngx_string("default");
    if (!(mcf->thread_pool = ngx_thread_pool_add(cf, mcf->thread_pool_name.len ? &mcf->thread_pool_name : &def))) return NGX_CONF_ERROR;
  }
#endif
  if (mcf->hash_key_file.len && fer_read_key(cf, mcf) != NGX_CONF_OK) return NGX_CONF_ERROR;
  Fi(ARRAY_LEN(dbs), if (dbs[i]->len && ngx_conf_full_name(cf->cycle, dbs[i], 0) != NGX_OK) return NGX_CONF_ERROR);
  return NGX_CONF_OK;
}

static void * fer_create_loc_conf(ngx_conf_t * cf) {
  fer_loc_conf_t * lcf = ngx_pcalloc(cf->pool, sizeof *lcf);
  if (!lcf) return NULL;
  lcf->enable = NGX_CONF_UNSET;  lcf->traps = NGX_CONF_UNSET_PTR;  lcf->tag = NGX_CONF_UNSET_PTR;
  return lcf;
}

static char * fer_merge_loc_conf(ngx_conf_t * cf, void * parent, void * child) {
  fer_loc_conf_t * prev = parent, * conf = child;
  ngx_conf_merge_value(conf->enable, prev->enable, 1);
  ngx_conf_merge_ptr_value(conf->traps, prev->traps, NULL);
  ngx_conf_merge_ptr_value(conf->tag, prev->tag, NULL);
  return NGX_CONF_OK;
}

static char * fer_set_shm(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
  fer_main_conf_t * mcf = conf;
  ngx_str_t * v = cf->args->elts;
  ssize_t size;
  if (mcf->zone) return "is duplicate";
  size = ngx_parse_size(&v[2]);
  if (size == NGX_ERROR || size < MiB(1)) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid zone size \"%V\" (min 1m)", &v[2]);
    return NGX_CONF_ERROR;
  }
  if (!(mcf->zone = ngx_shared_memory_add(cf, &v[1], (sz) size, &ngx_http_ferret_module))) return NGX_CONF_ERROR;
  if (mcf->zone->data) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate zone \"%V\"", &v[1]);
    return NGX_CONF_ERROR;
  }
  mcf->zone->init = fer_zone_init;
  return NGX_CONF_OK;
}

static char * fer_set_preset(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
  fer_main_conf_t * mcf = conf;
  ngx_str_t * v = (ngx_str_t *) cf->args->elts + 1;
  if (v->len < 1 || v->len > 2 || v->data[0] < '0' || v->data[0] > '9' || (v->len == 2 && v->data[1] != 'e'))
    return "must be 0..9, optionally followed by \"e\"";
  mcf->preset = (u32) (v->data[0] - '0') | (v->len == 2 ? LZMA_PRESET_EXTREME : 0);
  return NGX_CONF_OK;
}

static char * fer_set_retention(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
  fer_main_conf_t * mcf = conf;
  ngx_str_t * v = (ngx_str_t *) cf->args->elts + 1;
  if (mcf->retention != NGX_CONF_UNSET) return "is duplicate";
  if ((v->len == 2 && !ngx_strncmp(v->data, "-1", 2)) || (v->len == 3 && !ngx_strncmp(v->data, "off", 3))) mcf->retention = -1;
  else if ((mcf->retention = ngx_atoi(v->data, v->len)) == NGX_ERROR) {
    mcf->retention = NGX_CONF_UNSET;
    return "must be a number of days, or -1 / off to keep forever";
  }
  return NGX_CONF_OK;
}

static char * fer_set_list(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
  ngx_array_t ** a = (ngx_array_t **) ((char *) conf + cmd->offset);
  ngx_str_t * v = cf->args->elts, * s;
  ngx_uint_t i;
  if ((*a == NGX_CONF_UNSET_PTR || !*a) && !(*a = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t)))) return NGX_CONF_ERROR;
  for (i = 1; i < cf->args->nelts; i++) {
    if (!(s = ngx_array_push(*a))) return NGX_CONF_ERROR;
    *s = v[i];
    if (cmd->post) {
      if (!(s->data = ngx_pnalloc(cf->pool, s->len))) return NGX_CONF_ERROR;
      ngx_strlow(s->data, v[i].data, s->len);
    }
  }
  return NGX_CONF_OK;
}

#if (NGX_THREADS)
static char * fer_set_thread_pool(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
  fer_main_conf_t * mcf = conf;
  ngx_str_t * v = (ngx_str_t *) cf->args->elts + 1;
  if (v->len == 3 && !ngx_strncmp(v->data, "off", 3)) { mcf->thread_pool = (ngx_thread_pool_t *) -1;  ngx_str_set(&mcf->thread_pool_name, ""); }
  else mcf->thread_pool_name = *v;
  return NGX_CONF_OK;
}
#endif

static ngx_int_t fer_postconfiguration(ngx_conf_t * cf) {
  fer_main_conf_t * mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ferret_module);
  ngx_http_core_main_conf_t * cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  ngx_http_core_loc_conf_t * clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  ngx_http_handler_pt * h;
#if (NGX_THREADS)
  if (mcf->thread_pool == (ngx_thread_pool_t *) -1) mcf->thread_pool = NULL;
#endif
  if (!mcf->active) return NGX_OK;
  if (mcf->rdns) {
    if (!clcf->resolver || !clcf->resolver->connections.nelts) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"ferret_rdns on\" needs a \"resolver\" in the http{} block");
      return NGX_ERROR;
    }
    mcf->resolver = clcf->resolver;
  }
  if (!(h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers))) return NGX_ERROR;
  *h = fer_post_read_handler;
  if (!(h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers))) return NGX_ERROR;
  *h = fer_log_handler;
#if (NGX_HTTP_SSL)
  if (fer_install_ssl(cf) != NGX_OK) return NGX_ERROR;
#endif
  return NGX_OK;
}

/*  Process lifecycle.  */

/*  In the master, with the listening sockets open: ask the kernel to keep the SYN.  */
static ngx_int_t fer_init_module(ngx_cycle_t * cycle) {
  fer_main_conf_t * mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_ferret_module);
  ngx_listening_t * ls = cycle->listening.elts;
  ngx_uint_t i;
  int on = 1;
  if (!mcf || !mcf->active || !mcf->save_syn) return NGX_OK;
  Fi(cycle->listening.nelts,
    if (ls[i].fd == (ngx_socket_t) -1 || ls[i].type != SOCK_STREAM || ls[i].sockaddr->sa_family == AF_UNIX
        || ls[i].handler != ngx_http_init_connection) continue;
    if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_SAVE_SYN, &on, sizeof on) == -1)
      ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_socket_errno, "ferret: setsockopt(TCP_SAVE_SYN) on %V failed", &ls[i].addr_text));
  return NGX_OK;
}

static void fer_mmdb_open(ngx_cycle_t * cycle, ngx_str_t * path, MMDB_s * db, unsigned * open) {
  int rc;
  if (!path->len) return;
  if ((rc = MMDB_open((char *) path->data, MMDB_MODE_MMAP, db)) == MMDB_SUCCESS) *open = 1;
  else ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ferret: MMDB_open(\"%V\") failed: %s", path, MMDB_strerror(rc));
}

static ngx_int_t fer_init_process(ngx_cycle_t * cycle) {
  fer_main_conf_t * mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_ferret_module);
  ngx_listening_t * ls = cycle->listening.elts;
  ngx_uint_t i;
  char err[256];
  if (!mcf || !mcf->active) return NGX_OK;
  fer_mcf = mcf;
  fer_host();
  Fi(cycle->listening.nelts, if (ls[i].handler == ngx_http_init_connection) { fer_orig_handler = ls[i].handler;  ls[i].handler = fer_init_connection; });
  fer_mmdb_open(cycle, &mcf->geo_db, &fer_geo, &fer_geo_open);
  fer_mmdb_open(cycle, &mcf->asn_db, &fer_asn, &fer_asn_open);
  if (mcf->intel_db.len && fer_intel_open(&fer_intel, (char *) mcf->intel_db.data, err, sizeof err))
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ferret: %s", err);
  memset(&fer_timer, 0, sizeof fer_timer);  memset(&fer_timer_conn, 0, sizeof fer_timer_conn);
  fer_timer_conn.fd = (ngx_socket_t) -1;
  fer_timer.handler = fer_tick;  fer_timer.log = cycle->log;  fer_timer.data = &fer_timer_conn;  fer_timer.cancelable = 1;
  ngx_add_timer(&fer_timer, MIN(mcf->flush_interval, 10000));
  return NGX_OK;
}

static void fer_exit_process(ngx_cycle_t * cycle) {
  if (fer_geo_open) MMDB_close(&fer_geo);
  if (fer_asn_open) MMDB_close(&fer_asn);
  fer_geo_open = fer_asn_open = 0;
  fer_intel_close(&fer_intel);
  free(fer_rb.buf);  fer_rb.buf = NULL;  fer_rb.cap = 0;
}

/*  All workers are gone: flush what is left, the older buffer first.  */
static void fer_exit_master(ngx_cycle_t * cycle) {
  fer_main_conf_t * mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_ferret_module);
  ngx_uint_t i, idx;
  if (!mcf || !mcf->active || !fer_shm) return;
  fer_host();
  Fi(2,
    idx = (fer_shm->active + 1 + i) & 1;
    if (fer_shm->b[idx].used && fer_shm->b[idx].state != FER_BUF_IDLE) fer_flush_sync(mcf, idx, cycle->log));
  fer_shm->b[fer_shm->active].state = FER_BUF_FILL;
}
