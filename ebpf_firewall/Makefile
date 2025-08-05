#!/bin/bash
#iptables -A INPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
#xdp-loader unload -a ens38
#mkdir build
#clang -O2 -g -target bpf -c kernel/ebpf_firewall_kernel.c -o build/ebpf_firewall_kernel.o
#gcc -o build/ebpf_firewall_userspace userspace/src/ebpf_firewall_unix.c userspace/src/ebpf_firewall_log.c userspace/src/ebpf_firewall_core.c userspace/src/ebpf_firewall_config.c 
#-I userpsace/include -lbpf -lxdp -lnetfilter_conntrack -lpthread


CLANG        ?= clang
GCC          ?= gcc
BPF_ARCH     ?= bpf            # clang -target bpf
CLANG_FLAGS  := -O2 -g -target $(BPF_ARCH) -Wall -Wextra

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
KERNEL_OBJ   := $(BUILD_DIR)/ebpf_firewall_kernel.o

USR_SRCS     := userspace/src/ebpf_firewall_unix.c \
                userspace/src/ebpf_firewall_log.c  \
                userspace/src/ebpf_firewall_core.c \
                userspace/src/ebpf_firewall_config.c \
                userspace/src/ebpf_firewall_conntrack.c \
                userspace/src/ebpf_firewall_geo.c \
				userspace/src/base64.c

USR_CLI      := userspace/src/ebpf_firewall_cli.c
USR_PROM     := userspace/src/ebpf_fireall_exporter.c

USR_PROMBIN  := $(BUILD_DIR)/ebpf_firewall_prom
USR_BIN      := $(BUILD_DIR)/ebpf_firewall_userspace
USR_CLIBIN   := $(BUILD_DIR)/ebpf_firewall_cli
USR_INC_DIR  := userspace/include

INSTALL_DIR := /usr/local/share/ebpf_firewall

# Libraries
USR_LIBS     := -lbpf -lxdp -lnetfilter_conntrack -lpthread -lcrypto -lsqlite3
USR_PROMLIBS := -lprom -lpromhttp -lmicrohttpd -pthread


# ──────────────── Targets ────────────────
.PHONY: all unload run clean install test_mode production_mode

all: $(BUILD_DIR) unload $(KERNEL_OBJ) $(USR_BIN) $(USR_CLIBIN) $(USR_PROMBIN)

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
	$(GCC) -o $@ $^ -I$(USR_INC_DIR) $(USR_LIBS) -I. $(MODE_FLAGS)

$(USR_CLIBIN): $(USR_CLI) | $(BUILD_DIR)
	@echo ">> Linking userspace cli firewall"
	$(GCC) -o $@ $^

$(USR_PROMBIN): $(USR_PROM) | $(BUILD_DIR)
	@echo ">> Linking prometheus binary firewall"
	$(GCC) -o $@ $^ $(USR_PROMLIBS)

run: all
	@cd $(BUILD_DIR) && ./ebpf_firewall_userspace

clean:
	@rm -rf $(BUILD_DIR)

install: all
	@echo ">> Installing eBPF firewall to $(INSTALL_DIR)"
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo cp -r $(BUILD_DIR)/* $(INSTALL_DIR)/
	@echo "Installation complete. Files copied to $(INSTALL_DIR)"
	