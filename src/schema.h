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

/*  The columns.  Each block names its columns and their types, so readers
    need not know this list.  Columns may be appended; staging rows refer to
    them by index, so they are never renumbered while a running server, or one
    reloaded with the same binary, may still hold staged rows.  */

#ifndef FER_SCHEMA_H
#define FER_SCHEMA_H

#define FER_T_U   1     /*  unsigned varint  */
#define FER_T_S   2     /*  signed, zigzag varint  */
#define FER_T_TS  3     /*  signed, delta to previous present value  */
#define FER_T_B   4     /*  bytes (dictionary or raw, per block)  */

#define FER_TABLE_CONN  1
#define FER_TABLE_REQ   2

#define FER_CONN_COLUMNS(X)                                                   \
  X(CC_TS,            "ts",               FER_T_TS) /*  accept, us epoch  */  \
  X(CC_ID,            "conn_id",          FER_T_U)                          \
  X(CC_WORKER,        "worker_pid",       FER_T_U)                          \
  X(CC_LPORT,         "listen_port",      FER_T_U)                          \
  X(CC_SADDR,         "server_addr",      FER_T_B)                          \
  X(CC_CADDR,         "client_addr",      FER_T_B)  /*  4 or 16 bytes  */     \
  X(CC_CPORT,         "client_port",      FER_T_U)                          \
  /*  SYN fingerprint.  */                                                     \
  X(CC_SYN_MISSING,   "syn_missing",      FER_T_U)                          \
  X(CC_SYN_RAW,       "syn_raw",          FER_T_B)                          \
  X(CC_SYN_TTL,       "syn_ttl",          FER_T_U)                          \
  X(CC_SYN_DF,        "syn_df",           FER_T_U)                          \
  X(CC_SYN_IPID,      "syn_ipid",         FER_T_U)                          \
  X(CC_SYN_TOS,       "syn_tos",          FER_T_U)                          \
  X(CC_SYN_FLOW,      "syn_flowlabel",    FER_T_U)                          \
  X(CC_SYN_IPLEN,     "syn_iplen",        FER_T_U)                          \
  X(CC_SYN_IPOPT,     "syn_ipopt_len",    FER_T_U)                          \
  X(CC_SYN_WIN,       "syn_win",          FER_T_U)                          \
  X(CC_SYN_FLAGS,     "syn_flags",        FER_T_U)                          \
  X(CC_SYN_MSS,       "syn_mss",          FER_T_S)                          \
  X(CC_SYN_WS,        "syn_wscale",       FER_T_S)                          \
  X(CC_SYN_OPTS,      "syn_opts",         FER_T_B)                          \
  X(CC_SYN_TSVAL,     "syn_tsval",        FER_T_U)                          \
  X(CC_SYN_TSECR,     "syn_tsecr",        FER_T_U)                          \
  X(CC_SYN_PAYLOAD,   "syn_payload_len",  FER_T_U)                          \
  X(CC_SYN_URG,       "syn_urgptr",       FER_T_U)                          \
  X(CC_SYN_SEQ,       "syn_seq",          FER_T_U)                          \
  X(CC_SYN_ACKNZ,     "syn_ack_nonzero",  FER_T_U)                          \
  X(CC_JA4T,          "ja4t",             FER_T_B)                          \
  /*  TCP_INFO at accept / at ClientHello.  */                                 \
  X(CC_TA_RTT,        "tcp_acc_rtt_us",   FER_T_U)                          \
  X(CC_TA_RTTVAR,     "tcp_acc_rttvar_us",FER_T_U)                          \
  X(CC_TA_SNDMSS,     "tcp_acc_snd_mss",  FER_T_U)                          \
  X(CC_TA_RCVMSS,     "tcp_acc_rcv_mss",  FER_T_U)                          \
  X(CC_TA_ADVMSS,     "tcp_acc_advmss",   FER_T_U)                          \
  X(CC_TA_OPTS,       "tcp_acc_options",  FER_T_U)                          \
  X(CC_TA_SWS,        "tcp_acc_snd_wscale", FER_T_U)                        \
  X(CC_TA_RWS,        "tcp_acc_rcv_wscale", FER_T_U)                        \
  X(CC_TH_RTT,        "tcp_hello_rtt_us", FER_T_U)                          \
  X(CC_TH_RETR,       "tcp_hello_retrans",FER_T_U)                          \
  /*  TLS ClientHello.  */                                                     \
  X(CC_TLS,           "tls",              FER_T_U)                          \
  X(CC_TS_HELLO,      "ts_hello",         FER_T_TS)                         \
  X(CC_H_LEGACY,      "hello_legacy_version", FER_T_U)                      \
  X(CC_H_CIPHERS,     "hello_ciphers",    FER_T_B)  /*  raw u16be list  */    \
  X(CC_H_EXTS,        "hello_exts",       FER_T_B)  /*  raw ext block  */     \
  X(CC_H_COMP,        "hello_compression",FER_T_B)                          \
  X(CC_H_SIDLEN,      "hello_sid_len",    FER_T_U)                          \
  X(CC_SNI,           "sni",              FER_T_B)                          \
  X(CC_ALPN,          "alpn_offered",     FER_T_B)                          \
  X(CC_VERSIONS,      "tls_versions_offered", FER_T_B)                      \
  X(CC_GROUPS,        "groups_offered",   FER_T_B)                          \
  X(CC_SIGALGS,       "sigalgs_offered",  FER_T_B)                          \
  X(CC_KEYSHARE,      "keyshare_groups",  FER_T_B)                          \
  X(CC_GREASE,        "grease",           FER_T_U)                          \
  X(CC_JA4,           "ja4",              FER_T_B)                          \
  X(CC_JA4R,          "ja4_r",            FER_T_B)                          \
  X(CC_JA3,           "ja3",              FER_T_B)                          \
  X(CC_JA3H,          "ja3_hash",         FER_T_B)                          \
  /*  TLS outcome.  */                                                         \
  X(CC_TS_HS,         "ts_handshake_done",FER_T_TS)                         \
  X(CC_TLS_VER,       "tls_version",      FER_T_B)                          \
  X(CC_TLS_CIPHER,    "tls_cipher",       FER_T_B)                          \
  X(CC_TLS_GROUP,     "tls_group",        FER_T_B)                          \
  X(CC_TLS_ALPN,      "tls_alpn",         FER_T_B)                          \
  X(CC_TLS_REUSED,    "tls_reused",       FER_T_U)                          \
  X(CC_ALERT_SENT,    "tls_alert_sent",   FER_T_U)                          \
  X(CC_ALERT_RECV,    "tls_alert_recv",   FER_T_U)                          \
  /*  Lifetime.  */                                                            \
  X(CC_TS_CLOSE,      "ts_close",         FER_T_TS)                         \
  X(CC_NREQ,          "n_requests",       FER_T_U)                          \
  X(CC_BYTES_IN,      "bytes_in",         FER_T_U)                          \
  X(CC_BYTES_OUT,     "bytes_out",        FER_T_U)                          \
  X(CC_CLOSE,         "close_class",      FER_T_B)                          \
  X(CC_LAST_STATUS,   "last_status",      FER_T_U)                          \
  /*  Enrichment.  */                                                          \
  X(CC_COUNTRY,       "country",          FER_T_B)                          \
  X(CC_REGION,        "region",           FER_T_B)                          \
  X(CC_CITY,          "city",             FER_T_B)                          \
  X(CC_LAT,           "lat_e4",           FER_T_S)                          \
  X(CC_LON,           "lon_e4",           FER_T_S)                          \
  X(CC_ASN,           "asn",              FER_T_U)                          \
  X(CC_ASORG,         "as_org",           FER_T_B)                          \
  X(CC_INTEL,         "intel_tags",       FER_T_U)                          \
  X(CC_IPSUM,         "ipsum_score",      FER_T_U)                          \
  X(CC_INTEL_VER,     "intel_version",    FER_T_U)                          \
  /*  Reverse DNS (ferret_rdns on).  */                              \
  X(CC_RDNS_STATUS,   "rdns_status",      FER_T_B)                          \
  X(CC_RDNS_NAME,     "rdns_name",        FER_T_B)                          \
  X(CC_RDNS_FCRDNS,   "rdns_fcrdns",      FER_T_U)  /*  name -> same IP  */   \
  X(CC_RDNS_MS,       "rdns_ms",          FER_T_U)                          \
  /*  HTTP/2: the client's preface and frame counts.  */                       \
  X(CC_H2,            "h2",               FER_T_U)                          \
  X(CC_H2_SETTINGS,   "h2_settings",      FER_T_B)  /*  "id:value;..."  */    \
  X(CC_H2_WU,         "h2_window_update", FER_T_U)                          \
  X(CC_H2_PRIO,       "h2_priority",      FER_T_B)  /*  "sid:excl:dep:w,..." */ \
  X(CC_H2_PSEUDO,     "h2_pseudo",        FER_T_B)  /*  "m,a,s,p"  */         \
  X(CC_H2_HPRIO,      "h2_headers_priority", FER_T_B) /*  "excl:dep:w"  */    \
  X(CC_H2_FP,         "h2_fp",            FER_T_B)  /*  Akamai  */            \
  X(CC_H2_DATA,       "h2_n_data",        FER_T_U)                          \
  X(CC_H2_HEADERS,    "h2_n_headers",     FER_T_U)                          \
  X(CC_H2_PRIORITY,   "h2_n_priority",    FER_T_U)                          \
  X(CC_H2_RST,        "h2_n_rst_stream",  FER_T_U)                          \
  X(CC_H2_SETTINGSN,  "h2_n_settings",    FER_T_U)                          \
  X(CC_H2_PUSH,       "h2_n_push_promise",FER_T_U)                          \
  X(CC_H2_PING,       "h2_n_ping",        FER_T_U)                          \
  X(CC_H2_GOAWAY,     "h2_n_goaway",      FER_T_U)                          \
  X(CC_H2_WUN,        "h2_n_window_update", FER_T_U)                        \
  X(CC_H2_CONT,       "h2_n_continuation",FER_T_U)                          \
  X(CC_H2_OTHER,      "h2_n_other",       FER_T_U)                          \
  X(CC_H2_MAXSID,     "h2_max_stream",    FER_T_U)                          \
  X(CC_H2_GOAWAY_ERR, "h2_goaway_error",  FER_T_U)

#define FER_REQ_COLUMNS(X)                                                    \
  X(RC_TS,            "ts",               FER_T_TS) /*  request start  */     \
  X(RC_CONN,          "conn_id",          FER_T_U)                          \
  X(RC_SEQ,           "req_seq",          FER_T_U)                          \
  X(RC_TS_HDR,        "ts_headers",       FER_T_TS)                         \
  X(RC_TS_END,        "ts_end",           FER_T_TS)                         \
  X(RC_DUR,           "request_time_us",  FER_T_U)                          \
  X(RC_GAP,           "gap_us",           FER_T_S)                          \
  X(RC_METHOD,        "method",           FER_T_B)                          \
  X(RC_PATH,          "path",             FER_T_B)                          \
  X(RC_ARGS,          "args",             FER_T_B)                          \
  X(RC_PROTO,         "protocol",         FER_T_B)                          \
  X(RC_RLINE,         "request_line_abnormal", FER_T_B)                     \
  X(RC_HOST,          "host",             FER_T_B)                          \
  X(RC_SERVER,        "server_name",      FER_T_B)                          \
  X(RC_SNI_MISMATCH,  "sni_host_mismatch",FER_T_U)                          \
  X(RC_HNAMES,        "header_names",     FER_T_B)                          \
  X(RC_HCOUNT,        "header_count",     FER_T_U)                          \
  X(RC_HBYTES,        "header_bytes",     FER_T_U)                          \
  X(RC_HDUP,          "header_dup",       FER_T_U)                          \
  X(RC_H_UA,          "h_user_agent",     FER_T_B)                          \
  X(RC_H_ACCEPT,      "h_accept",         FER_T_B)                          \
  X(RC_H_ALANG,       "h_accept_language",FER_T_B)                          \
  X(RC_H_AENC,        "h_accept_encoding",FER_T_B)                          \
  X(RC_H_REFERER,     "h_referer",        FER_T_B)                          \
  X(RC_H_ORIGIN,      "h_origin",         FER_T_B)                          \
  X(RC_H_CONNECTION,  "h_connection",     FER_T_B)                          \
  X(RC_H_CACHECTL,    "h_cache_control",  FER_T_B)                          \
  X(RC_H_PRAGMA,      "h_pragma",         FER_T_B)                          \
  X(RC_H_UPGRADE,     "h_upgrade",        FER_T_B)                          \
  X(RC_H_CTYPE,       "h_content_type",   FER_T_B)                          \
  X(RC_H_CLEN,        "h_content_length", FER_T_B)                          \
  X(RC_H_TE,          "h_transfer_encoding", FER_T_B)                       \
  X(RC_H_XRW,         "h_x_requested_with", FER_T_B)                        \
  X(RC_H_DNT,         "h_dnt",            FER_T_B)                          \
  X(RC_H_GPC,         "h_sec_gpc",        FER_T_B)                          \
  X(RC_H_SFSITE,      "h_sec_fetch_site", FER_T_B)                          \
  X(RC_H_SFMODE,      "h_sec_fetch_mode", FER_T_B)                          \
  X(RC_H_SFDEST,      "h_sec_fetch_dest", FER_T_B)                          \
  X(RC_H_SFUSER,      "h_sec_fetch_user", FER_T_B)                          \
  X(RC_H_CHUA,        "h_sec_ch_ua",      FER_T_B)                          \
  X(RC_H_CHMOB,       "h_sec_ch_ua_mobile", FER_T_B)                        \
  X(RC_H_CHPLAT,      "h_sec_ch_ua_platform", FER_T_B)                      \
  X(RC_H_PRIORITY,    "h_priority",       FER_T_B)                          \
  X(RC_H_UIR,         "h_upgrade_insecure_requests", FER_T_B)               \
  X(RC_H_XFF,         "h_x_forwarded_for",FER_T_B)                          \
  X(RC_H_XRIP,        "h_x_real_ip",      FER_T_B)                          \
  X(RC_H_FORWARDED,   "h_forwarded",      FER_T_B)                          \
  X(RC_H_VIA,         "h_via",            FER_T_B)                          \
  X(RC_H_TEH,         "h_te",             FER_T_B)                          \
  X(RC_H_RANGE,       "h_range",          FER_T_B)                          \
  X(RC_H_INM,         "h_if_none_match",  FER_T_B)                          \
  X(RC_H_IMS,         "h_if_modified_since", FER_T_B)                       \
  X(RC_H_EXPECT,      "h_expect",         FER_T_B)                          \
  X(RC_H_EXTRA,       "h_extra",          FER_T_B)  /*  configured extras  */ \
  X(RC_AUTH_SCHEME,   "auth_scheme",      FER_T_B)                          \
  X(RC_AUTH_HASH,     "auth_hash",        FER_T_B)                          \
  X(RC_XMATRIX,       "xmatrix_origin",   FER_T_B)                          \
  X(RC_COOKIE_NAMES,  "cookie_names",     FER_T_B)                          \
  X(RC_COOKIE_HASHES, "cookie_hashes",    FER_T_B)                          \
  X(RC_REQ_LEN,       "request_length",   FER_T_U)                          \
  X(RC_STATUS,        "status",           FER_T_U)                          \
  X(RC_BYTES_SENT,    "bytes_sent",       FER_T_U)                          \
  X(RC_BODY_SENT,     "body_bytes_sent",  FER_T_U)                          \
  X(RC_RESP_CTYPE,    "resp_content_type",FER_T_B)                          \
  X(RC_RESP_LOC,      "resp_location",    FER_T_B)                          \
  X(RC_RESP_SETCK,    "resp_set_cookie_count", FER_T_U)                     \
  X(RC_KEEPALIVE,     "keepalive",        FER_T_U)                          \
  X(RC_UP_ADDR,       "up_addr",          FER_T_B)                          \
  X(RC_UP_STATUS,     "up_status",        FER_T_U)                          \
  X(RC_UP_CONNECT,    "up_connect_ms",    FER_T_S)                          \
  X(RC_UP_HEADER,     "up_header_ms",     FER_T_S)                          \
  X(RC_UP_RESPONSE,   "up_response_ms",   FER_T_S)                          \
  X(RC_UP_TRIES,      "up_tries",         FER_T_U)                          \
  X(RC_UP_BIN,        "up_bytes_received",FER_T_U)                          \
  X(RC_UP_BOUT,       "up_bytes_sent",    FER_T_U)                          \
  X(RC_T_RTT,         "tcp_rtt_us",       FER_T_U)                          \
  X(RC_T_RTTVAR,      "tcp_rttvar_us",    FER_T_U)                          \
  X(RC_T_MINRTT,      "tcp_min_rtt_us",   FER_T_U)                          \
  X(RC_T_RETRANS,     "tcp_total_retrans",FER_T_U)                          \
  X(RC_T_RATE,        "tcp_delivery_rate",FER_T_U)                          \
  X(RC_T_CWND,        "tcp_snd_cwnd",     FER_T_U)                          \
  X(RC_T_ACKED,       "tcp_bytes_acked",  FER_T_U)                          \
  X(RC_T_RECV,        "tcp_bytes_received", FER_T_U)                        \
  X(RC_TRAP,          "trap_hit",         FER_T_U)                          \
  X(RC_TAG,           "tag",              FER_T_B)                          \
  X(RC_H2_STREAM,     "h2_stream",        FER_T_U)                          \
  X(RC_H2_WEIGHT,     "h2_weight",        FER_T_U)                          \
  X(RC_H2_PARENT,     "h2_parent",        FER_T_U)

#define FER_X_ENUM(e, n, t)  e,

enum { FER_CONN_COLUMNS(FER_X_ENUM) FER_CONN_NCOLS };
enum { FER_REQ_COLUMNS(FER_X_ENUM)  FER_REQ_NCOLS };

#endif
