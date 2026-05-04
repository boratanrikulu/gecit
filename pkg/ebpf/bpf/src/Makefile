# BPF build — clang-compiles sockops.bpf.c (gobee output) into per-arch
# .bpf.o files under ../bin/. Requires: clang with BPF target, llvm-strip.

CFLAGS := -Wall -Werror -O2 -g

OUTPUT_DIR_X86 := ../bin/x86
OUTPUT_DIR_ARM := ../bin/arm64
INCLUDE_DIR := ../../../../include

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_TARGET := bpfel

# On Debian/Ubuntu, asm/types.h lives under the multiarch include path
# instead of /usr/include/asm. Add it to the include search path so
# `#include <linux/bpf.h>` resolves regardless of host arch.
HOST_ARCH := $(shell uname -m)
MULTIARCH_INCLUDE := /usr/include/$(HOST_ARCH)-linux-gnu

BPF_CFLAGS := $(CFLAGS) -target $(BPF_TARGET) -I$(INCLUDE_DIR) -I$(MULTIARCH_INCLUDE)

ENTRYPOINT_SRC := sockops.bpf.c

OUTPUTS_X86 := $(OUTPUT_DIR_X86)/sockops.bpf.o
OUTPUTS_ARM := $(OUTPUT_DIR_ARM)/sockops.bpf.o
OUTPUTS := $(OUTPUTS_X86) $(OUTPUTS_ARM)

.PHONY: bpf-all bpf-clean

bpf-all: $(OUTPUTS)

$(OUTPUT_DIR_X86)/sockops.bpf.o: $(ENTRYPOINT_SRC)
	@mkdir -p $(OUTPUT_DIR_X86)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@
	$(LLVM_STRIP) -g $@

$(OUTPUT_DIR_ARM)/sockops.bpf.o: $(ENTRYPOINT_SRC)
	@mkdir -p $(OUTPUT_DIR_ARM)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_arm64 -c $< -o $@
	$(LLVM_STRIP) -g $@

bpf-clean:
	@rm -f $(OUTPUTS)
