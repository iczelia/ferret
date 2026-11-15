SHELL = /bin/bash
NGX = /usr/share/nginx/src
CFLAGS = -g -O2 -fstack-protector-strong -fPIC -D_FORTIFY_SOURCE=2 -Wall -Werror
LDFLAGS = -Wl,-z,relro -Wl,-z,now -fPIC
SAN = -fsanitize=address,undefined
PRELOAD = LD_PRELOAD=$(shell gcc -print-file-name=libasan.so):$(shell gcc -print-file-name=libubsan.so)
SRC = $(wildcard src/*.c src/*.h) src/config

# $(call module,objdir,cflags,ldflags,out)
define module
	rm -rf $(1) && cp -a $(NGX) $(1)
	cd $(1) && . ./conf_flags && ./configure "$${NGX_CONF_FLAGS[@]}" \
	  --with-cc-opt="$(CFLAGS) $(2)" --with-ld-opt="$(LDFLAGS) $(3)" \
	  --add-dynamic-module=$(CURDIR)/src > configure.log || { tail -40 configure.log; exit 1; }
	$(MAKE) -C $(1) -f objs/Makefile modules > $(1)/make.log || { grep -A6 error $(1)/make.log; exit 1; }
	mkdir -p $(dir $(4)) && cp $(1)/objs/ngx_http_ferret_module.so $(4)
endef

all: out/ngx_http_ferret_module.so

out/ngx_http_ferret_module.so: $(SRC)
	$(call module,/tmp/ngx-build,,,$@)

out/asan/ngx_http_ferret_module.so: $(SRC)
	$(call module,/tmp/ngx-asan,$(SAN) -fno-omit-frame-pointer,$(SAN),$@)

load: all
	bash tests/load.sh

clean:
	rm -rf out

.PHONY: all test load clean
