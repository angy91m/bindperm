# bindperm - build and install
CLANG    ?= clang
BPFTOOL  ?= bpftool
PREFIX   ?= /usr/local
SBINDIR  ?= $(PREFIX)/sbin
SYSCONF  ?= /etc
UNITDIR  ?= /etc/systemd/system
DESTDIR  ?=

# On Debian, bpftool lives in /usr/sbin, which is not in a normal user's PATH
export PATH := $(PATH):/usr/sbin:/sbin

BUILD ?= build

# make STATIC=1 builds a binary that does not need libbpf at runtime
ifeq ($(STATIC),1)
LDFLAGS += -static
endif

all: $(BUILD)/bindperm

$(BUILD):
	mkdir -p $@

# Types of the running kernel; CO-RE relocates fields at load time,
# so the target kernel may differ from the build kernel.
$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

ARCH_INC := /usr/include/$(shell uname -m)-linux-gnu

$(BUILD)/bindperm.bpf.o: src/bindperm.bpf.c src/bindperm.h $(BUILD)/vmlinux.h
	$(CLANG) -g -O2 -target bpf -I$(BUILD) -Isrc -I$(ARCH_INC) -c $< -o $@

$(BUILD)/bindperm.skel.h: $(BUILD)/bindperm.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/bindperm: src/bindperm.c src/bindperm.h $(BUILD)/bindperm.skel.h
	$(CC) -O2 -Wall -I$(BUILD) -Isrc $(LDFLAGS) -o $@ src/bindperm.c -lbpf -lelf -lz

# Unit template: substitute the install path of the binary
$(BUILD)/bindperm.service: systemd/bindperm.service.in | $(BUILD)
	sed 's|@SBINDIR@|$(SBINDIR)|g; s|@SYSCONF@|$(SYSCONF)|g' $< > $@

check-requirements:
	bash scripts/check-requirements.sh

# Installs binary, unit and, only if absent, the default configuration.
# Does not enable or start the service.
install: all $(BUILD)/bindperm.service
	install -D -m755 $(BUILD)/bindperm $(DESTDIR)$(SBINDIR)/bindperm
	install -D -m644 $(BUILD)/bindperm.service $(DESTDIR)$(UNITDIR)/bindperm.service
	install -d -m755 -o root -g root $(DESTDIR)$(SYSCONF)/bindperm.d
	test -e $(DESTDIR)$(SYSCONF)/bindperm.conf || \
	    install -D -m644 -o root -g root etc/bindperm.conf $(DESTDIR)$(SYSCONF)/bindperm.conf
	@echo
	@echo "Installed. Edit $(SYSCONF)/bindperm.conf, then:"
	@echo "  sudo $(SBINDIR)/bindperm -C       # dry run: verifier + CO-RE, nothing attached"
	@echo "  sudo systemctl daemon-reload && sudo systemctl enable --now bindperm"

# Keeps the configuration files.
uninstall:
	-systemctl disable --now bindperm 2>/dev/null
	rm -f $(DESTDIR)$(SBINDIR)/bindperm $(DESTDIR)$(UNITDIR)/bindperm.service

clean:
	rm -rf $(BUILD)

.PHONY: all check-requirements install uninstall clean