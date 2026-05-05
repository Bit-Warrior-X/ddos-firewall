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

LIBBPF_INCLUDE ?= $(VMLINUX_SRC)/tools/bpf/resolve_btfids/libbpf/include
ifneq ("$(wildcard $(LIBBPF_INCLUDE)/bpf/bpf_helpers.h)","")
CLANG_FLAGS += -I$(LIBBPF_INCLUDE)
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

USR_PROMBIN  := $(BUILD_DIR)/ebpf_firewall_prom
USR_BIN      := $(BUILD_DIR)/sparta_user
USR_CLIBIN   := $(BUILD_DIR)/sparta_cli
USR_INC_DIR  := userspace/include

USR_INCLUDES = -I$(USR_INC_DIR) -I. $(MODE_FLAGS)
ifneq ("$(wildcard $(LIBBPF_INCLUDE)/bpf/libbpf.h)","")
USR_INCLUDES += -I$(LIBBPF_INCLUDE)
endif

INSTALL_DIR := /usr/local/share/dorian/sparta

# Libraries
USR_LIBS     := -lbpf -lxdp -lnetfilter_conntrack -lpthread -lcrypto -lsqlite3
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
	
