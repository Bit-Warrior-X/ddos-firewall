#!/bin/bash
#iptables -A INPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
#xdp-loader unload -a ens38
#mkdir build
#clang -O2 -g -target bpf -c kernel/ebpf_firewall_kernel.c -o build/ebpf_firewall_kernel.o
#gcc -o build/ebpf_firewall_userspace userspace/src/ebpf_firewall_unix.c userspace/src/ebpf_firewall_log.c userspace/src/ebpf_firewall_core.c userspace/src/ebpf_firewall_config.c 
#-I userpsace/include -lbpf -lxdp -lnetfilter_conntrack -lpthread


CLANG        ?= clang
GCC          ?= gcc
BPF_ARCH     ?= bpf            # clang -target bpf
ARCH         ?= x86
KERNEL_RELEASE ?= $(shell uname -r)
KERNEL_HEADERS ?= /lib/modules/$(KERNEL_RELEASE)/build
VMLINUX      ?= $(KERNEL_HEADERS)
VMLINUX_SRC  ?= /usr/src/linux-headers-$(KERNEL_RELEASE)
MULTIARCH    ?= $(shell $(GCC) -print-multiarch 2>/dev/null)

ifeq ("$(wildcard $(VMLINUX)/include)","")
VMLINUX := /usr/src/linux-headers-$(shell echo $(KERNEL_RELEASE) | sed 's/-.*//')
endif
CLANG_FLAGS  := -O2 -g -target $(BPF_ARCH) -Wall -Wextra \
							   -I/usr/include \
							   $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH),) \
							   -D__TARGET_ARCH_$(ARCH)

# Kernel tree headers (eBPF object only — not for userspace link).
LIBBPF_KERNEL_INCLUDE ?= $(VMLINUX_SRC)/tools/bpf/resolve_btfids/libbpf/include

# Userspace needs libbpf >= 0.7 (bpf_xdp_attach, bpf_object__next_map). Jammy apt is 0.5.
# Prefer /usr/local from xdp-tools; do not use pkg-config when it still points at 0.5.
LOCAL_LIBBPF_SO := $(firstword $(wildcard /usr/local/lib/libbpf.so*))
LOCAL_LIBBPF_A  := $(wildcard /usr/local/lib/libbpf.a)
libbpf_local_ok := $(shell \
  if [ -n "$(LOCAL_LIBBPF_SO)" ] && nm -D "$(LOCAL_LIBBPF_SO)" 2>/dev/null | grep -q 'bpf_xdp_attach'; then \
    echo yes; \
  elif [ -f /usr/local/lib/libbpf.a ] && nm /usr/local/lib/libbpf.a 2>/dev/null | grep -q 'bpf_xdp_attach'; then \
    echo yes; \
  else \
    echo no; \
  fi)

ifeq ($(libbpf_local_ok),yes)
  LIBBPF_USR_CFLAGS := -I/usr/local/include
  ifneq ($(LOCAL_LIBBPF_SO),)
    LIBBPF_LIBS := -L/usr/local/lib -Wl,-rpath,/usr/local/lib -lbpf
  else
    LIBBPF_LIBS := -L/usr/local/lib -l:libbpf.a -lelf -lz
  endif
  $(info Using libbpf from /usr/local ($(if $(LOCAL_LIBBPF_SO),$(LOCAL_LIBBPF_SO),libbpf.a)))
else
  PKG_CONFIG_PATH ?= /usr/local/lib/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig
  export PKG_CONFIG_PATH
  LIBBPF_USR_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
  LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null)
  ifeq ($(LIBBPF_LIBS),)
    LIBBPF_LIBS := -lbpf
  endif
  $(info Using libbpf from pkg-config: $(LIBBPF_LIBS))
endif

ifneq ("$(wildcard $(LIBBPF_KERNEL_INCLUDE)/bpf/bpf_helpers.h)","")
CLANG_FLAGS += -I$(LIBBPF_KERNEL_INCLUDE)
endif
ifneq ($(LIBBPF_USR_CFLAGS),)
CLANG_FLAGS += $(LIBBPF_USR_CFLAGS)
endif

# Build mode (default: production_mode)
BUILD_MODE   ?= production_mode

# Compiler flags based on mode
ifeq ($(BUILD_MODE),test_mode)
    MODE_FLAGS := -DTEST_MODE
else
    MODE_FLAGS := -DPRODUCTION_MODE
endif

# Paths
BUILD_DIR    := build
KERNEL_SRC   := kernel/ebpf_firewall_kernel.c
KERNEL_OBJ   := $(BUILD_DIR)/sparta_kernel.o

USR_SRCS     := userspace/src/ebpf_firewall_unix.c \
                userspace/src/ebpf_firewall_log.c  \
                userspace/src/ebpf_firewall_core.c \
                userspace/src/ebpf_firewall_config.c \
                userspace/src/ebpf_firewall_conntrack.c \
                userspace/src/ebpf_firewall_geo.c \
                userspace/src/ebpf_firewall_nginx.c \
				userspace/src/ebpf_firewall_utils.c \
				userspace/src/base64.c

USR_CLI      := userspace/src/ebpf_firewall_cli.c
USR_PROM     := userspace/src/ebpf_fireall_exporter.c

USR_PROMBIN  := $(BUILD_DIR)/sparta_prom
USR_BIN      := $(BUILD_DIR)/sparta_user
USR_CLIBIN   := $(BUILD_DIR)/sparta_cli
USR_INC_DIR  := userspace/include

USR_INCLUDES = -I$(USR_INC_DIR) -I. $(MODE_FLAGS) $(LIBBPF_USR_CFLAGS)

INSTALL_DIR := /usr/local/share/dorian/sparta

USR_LIBS     := $(LIBBPF_LIBS) -lnetfilter_conntrack -lpthread -lcrypto -lsqlite3
USR_PROMLIBS := -lprom -lpromhttp -lmicrohttpd -pthread

PROM_ENABLED := $(if $(wildcard /usr/include/prom.h),$(if $(wildcard /usr/include/promhttp.h),1,0),0)
ifeq ($(PROM_ENABLED),1)
PROM_TARGET := $(USR_PROMBIN)
else
PROM_TARGET :=
endif


# ──────────────── Targets ────────────────
.PHONY: all unload run clean install test_mode production_mode

all: $(BUILD_DIR) unload $(KERNEL_OBJ) $(USR_BIN) $(USR_CLIBIN) $(PROM_TARGET)

production_mode:
	$(MAKE) BUILD_MODE=production_mode all
test_mode:
	$(MAKE) BUILD_MODE=test_mode all

# 1. Build directory
$(BUILD_DIR):
	@mkdir -p $@
	cp firewall.config build/
	mkdir build/geodb
	cp geodb/* build/geodb/

# 2. Compile eBPF object
$(KERNEL_OBJ): $(KERNEL_SRC) | $(BUILD_DIR)
	@echo ">> Compiling eBPF kernel object"
	$(CLANG)  -I. $(CLANG_FLAGS) -c $< -o $@

# 3. Compile userspace binary
$(USR_BIN): $(USR_SRCS) | $(BUILD_DIR)
	@echo ">> Linking userspace firewall"
	@echo ">> LIBBPF_LIBS=$(LIBBPF_LIBS)"
	$(GCC) -o $@ $^ $(USR_INCLUDES) $(USR_LIBS)

$(USR_CLIBIN): $(USR_CLI) | $(BUILD_DIR)
	@echo ">> Linking userspace cli firewall"
	$(GCC) -o $@ $^

$(USR_PROMBIN): $(USR_PROM) | $(BUILD_DIR)
	@echo ">> Linking prometheus binary firewall"
	$(GCC) -o $@ $^ $(USR_PROMLIBS)

run: all
	@cd $(BUILD_DIR) && ./sparta_user

clean:
	@rm -rf $(BUILD_DIR)

install: all
	@echo ">> Installing eBPF firewall to $(INSTALL_DIR)"
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo cp -r $(BUILD_DIR)/* $(INSTALL_DIR)/
	@echo "Installation complete. Files copied to $(INSTALL_DIR)"
