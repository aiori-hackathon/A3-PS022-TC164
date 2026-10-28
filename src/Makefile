CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

# Interface for `make run`
IFACE   ?= enp1s0f0np0

BPF_CFLAGS  := -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -I.
USER_CFLAGS := -O2 -g -Wall -Wextra -I.
USER_LIBS   := -lbpf -lelf -lz

.PHONY: all setup run clean

all: dns_tracer

dns_tracer.bpf.o: dns_tracer.bpf.c common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

dns_tracer.skel.h: dns_tracer.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

dns_tracer: dns_tracer.c common.h dns_tracer.skel.h
	$(CC) $(USER_CFLAGS) dns_tracer.c -o $@ $(USER_LIBS)

setup:
	sudo apt-get update
	sudo apt-get install -y clang llvm gcc make pkg-config libbpf-dev \
		libelf-dev zlib1g-dev linux-tools-common linux-tools-$$(uname -r)

run: all
	sudo ./dns_tracer $(IFACE)

clean:
	rm -f dns_tracer dns_tracer.bpf.o dns_tracer.skel.h