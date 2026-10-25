# ============================================================
# DNS Tracer - CloudLab eBPF/XDP/TC
# ============================================================

BPF_SRC      := dns_tracer.bpf.c
BPF_OBJ      := dns_tracer.bpf.o

USER_SRC     := dns_tracer.c
PARSER_SRC   := dns_parser.c
PARSER_HDR   := dns_parser.h
JSON_SRC     := json_logger.c
JSON_HDR     := json_logger.h

TRACER       := dns_tracer

SKEL         := dns_tracer.skel.h

CLANG        ?= clang
CC           ?= gcc
BPFTOOL      ?= bpftool

# CloudLab interface
IFACE        ?= enp1s0f0np0

# Directory for generated JSON files
JSON_DIR     ?= json


# ============================================================
# Compiler flags
# ============================================================

BPF_CFLAGS   := -O2 -g -target bpf \
                -I/usr/include/x86_64-linux-gnu \
                -I. \
                -Wno-pass-failed

USER_CFLAGS  := -O2 -g -Wall -Wextra \
                -I.

USER_LIBS    := -lbpf -lelf -lz


# ============================================================
# Default
# ============================================================

.PHONY: all
all: build


# ============================================================
# Install dependencies
# ============================================================

.PHONY: setup

setup:
	@echo ""
	@echo "=============================================="
	@echo " Installing eBPF dependencies"
	@echo "=============================================="
	@echo ""

	sudo apt-get update

	sudo apt-get install -y \
		clang \
		llvm \
		gcc \
		make \
		pkg-config \
		libbpf-dev \
		libelf-dev \
		zlib1g-dev \
		iproute2 \
		linux-tools-common

	@echo ""
	@echo "Trying kernel-specific Linux tools..."

	sudo apt-get install -y linux-tools-$$(uname -r) 2>/dev/null || \
		echo "WARNING: linux-tools-$$(uname -r) not available."

	@echo ""
	@echo "=============================================="
	@echo " Installed versions"
	@echo "=============================================="
	@echo ""

	@echo "clang:"
	$(CLANG) --version | head -n 1

	@echo ""
	@echo "gcc:"
	$(CC) --version | head -n 1

	@echo ""
	@echo "bpftool:"
	$(BPFTOOL) version || true

	@echo ""
	@echo "libbpf:"
	pkg-config --modversion libbpf || true

	@echo ""
	@echo "Kernel:"
	uname -r

	@echo ""
	@echo "Architecture:"
	uname -m

	@echo ""
	@echo "Interfaces:"
	ip -br link

	@echo ""
	@echo "=============================================="
	@echo " Setup complete"
	@echo "=============================================="


# ============================================================
# JSON output directory
# ============================================================

.PHONY: json-dir

json-dir:
	@mkdir -p $(JSON_DIR)


# ============================================================
# Compile BPF program
# ============================================================

$(BPF_OBJ): $(BPF_SRC) common.h xdp.h tc.h
	@echo ""
	@echo "=============================================="
	@echo " Compiling BPF program"
	@echo "=============================================="
	@echo ""

	$(CLANG) \
		$(BPF_CFLAGS) \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)

	@echo ""
	@echo "Created: $(BPF_OBJ)"


# ============================================================
# Generate libbpf skeleton
# ============================================================

$(SKEL): $(BPF_OBJ)
	@echo ""
	@echo "=============================================="
	@echo " Generating libbpf skeleton"
	@echo "=============================================="
	@echo ""

	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

	@echo ""
	@echo "Created: $(SKEL)"


# ============================================================
# Build userspace tracer
# ============================================================

$(TRACER): $(USER_SRC) $(PARSER_SRC) $(PARSER_HDR) \
           $(JSON_SRC) $(JSON_HDR) $(SKEL)
	@echo ""
	@echo "=============================================="
	@echo " Building userspace tracer"
	@echo "=============================================="
	@echo ""

	$(CC) \
		$(USER_CFLAGS) \
		$(USER_SRC) \
		$(PARSER_SRC) \
		$(JSON_SRC) \
		-o $(TRACER) \
		$(USER_LIBS)

	@echo ""
	@echo "Created: $(TRACER)"


# ============================================================
# Build everything
# ============================================================

.PHONY: build

build: $(BPF_OBJ) $(SKEL) $(TRACER) json-dir

	@echo ""
	@echo "=============================================="
	@echo " BUILD COMPLETE"
	@echo "=============================================="
	@echo ""
	@echo "BPF object : $(BPF_OBJ)"
	@echo "Skeleton   : $(SKEL)"
	@echo "Tracer     : $(TRACER)"
	@echo "JSON dir   : $(JSON_DIR)"
	@echo ""


# ============================================================
# Run
#
# Usage:
#
#   make run
#
#   make run IFACE=enp1s0f0np0
#
# ============================================================

.PHONY: run

run: build
	@echo ""
	@echo "=============================================="
	@echo " Running DNS tracer"
	@echo "=============================================="
	@echo ""
	@echo "Interface: $(IFACE)"
	@echo "JSON dir : $(JSON_DIR)"
	@echo ""
	@echo "Press Ctrl+C to stop."
	@echo ""

	sudo ./$(TRACER) $(IFACE)


# ============================================================
# Run with a clean JSON directory
# ============================================================

.PHONY: run-clean

run-clean: clean-json build
	@echo ""
	@echo "Starting DNS tracer with clean JSON output..."
	@echo ""

	sudo ./$(TRACER) $(IFACE)


# ============================================================
# Clean JSON files
# ============================================================

.PHONY: clean-json

clean-json:
	@echo "Removing generated JSON files..."
	rm -rf $(JSON_DIR)


# ============================================================
# Show available interfaces
# ============================================================

.PHONY: interfaces

interfaces:
	ip -br link


# ============================================================
# Show loaded BPF programs
# ============================================================

.PHONY: programs

programs:
	sudo $(BPFTOOL) prog list


# ============================================================
# Show BPF links
# ============================================================

.PHONY: links

links:
	sudo $(BPFTOOL) link list


# ============================================================
# Show BPF networking attachments
# ============================================================

.PHONY: net

net:
	sudo $(BPFTOOL) net show


# ============================================================
# Show all useful status information
# ============================================================

.PHONY: status

status:
	@echo ""
	@echo "=============================================="
	@echo " BPF programs"
	@echo "=============================================="
	@echo ""

	sudo $(BPFTOOL) prog list

	@echo ""
	@echo "=============================================="
	@echo " BPF links"
	@echo "=============================================="
	@echo ""

	sudo $(BPFTOOL) link list

	@echo ""
	@echo "=============================================="
	@echo " Network attachments"
	@echo "=============================================="
	@echo ""

	sudo $(BPFTOOL) net show


# ============================================================
# Kernel bpf_printk() output
# ============================================================

.PHONY: trace

trace:
	@echo ""
	@echo "Reading kernel BPF trace output..."
	@echo "Press Ctrl+C to stop."
	@echo ""

	sudo cat /sys/kernel/debug/tracing/trace_pipe


# ============================================================
# Inspect BPF object
# ============================================================

.PHONY: inspect

inspect: $(BPF_OBJ)
	llvm-objdump -S $(BPF_OBJ)


# ============================================================
# Show BPF object information
# ============================================================

.PHONY: bpf-info

bpf-info: $(BPF_OBJ)
	$(BPFTOOL) prog loadall $(BPF_OBJ) /sys/fs/bpf/dns_tracer_test


# ============================================================
# Clean build artifacts
# ============================================================

.PHONY: clean

clean:
	@echo "Removing generated files..."

	rm -f $(BPF_OBJ)
	rm -f $(SKEL)
	rm -f $(TRACER)

	@echo "Build artifacts removed."


# ============================================================
# Clean everything including JSON
# ============================================================

.PHONY: clean-all

clean-all: clean clean-json

	@echo ""
	@echo "Everything cleaned."
	@echo ""


# ============================================================
# Help
# ============================================================

.PHONY: help

help:
	@echo ""
	@echo "DNS Tracer"
	@echo ""
	@echo "Setup:"
	@echo "  make setup"
	@echo ""
	@echo "Build:"
	@echo "  make"
	@echo "  make build"
	@echo ""
	@echo "Run:"
	@echo "  make run"
	@echo "  make run IFACE=enp1s0f0np0"
	@echo "  make run-clean"
	@echo ""
	@echo "JSON:"
	@echo "  make clean-json"
	@echo ""
	@echo "Debug:"
	@echo "  make trace"
	@echo "  make status"
	@echo "  make programs"
	@echo "  make links"
	@echo "  make net"
	@echo ""
	@echo "Other:"
	@echo "  make interfaces"
	@echo "  make inspect"
	@echo "  make bpf-info"
	@echo "  make clean"
	@echo "  make clean-all"
	@echo ""