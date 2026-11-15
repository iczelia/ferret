#!/bin/bash
set -euo pipefail
install -D -m 0644 out/ngx_http_ferret_module.so /usr/lib/nginx/modules/ngx_http_ferret_module.so
install -m 0644 contrib/mod-http-ferret.conf /etc/nginx/modules-enabled/
install -d -m 0750 -o www-data -g adm /var/log/ferret
install -d -m 0755 /var/lib/ferret
install -d -m 0700 /etc/ferret
[ -s /etc/ferret/hash.key ] || { head -c 32 /dev/urandom > /etc/ferret/hash.key; chmod 0600 /etc/ferret/hash.key; }
install -m 0755 tools/ferret-intel tools/ferret-geo tools/ferread.py /usr/local/bin/
install -m 0644 contrib/*.service contrib/*.timer /etc/systemd/system/
install -m 0644 contrib/ferret.sysusers /usr/lib/sysusers.d/ferret.conf
systemd-sysusers
chown ferret: /var/lib/ferret
systemctl daemon-reload
systemctl start ferret-geo.service ferret-intel.service   # first fetch
systemctl enable --now ferret-geo.timer ferret-intel.timer
echo "now: include contrib/ferret.conf in http{}, then: nginx -t && systemctl reload nginx"
