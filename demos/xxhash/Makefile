LLVM_CONFIG ?= llvm-config
LLVM_BIN_DIR = $(shell $(LLVM_CONFIG) --bindir)
CLANG=$(LLVM_BIN_DIR)/clang


all: prove

prove: xxhash32-ref.bc xxhash64-ref.bc
	saw xxhash32-ref.saw
	saw xxhash64-ref.saw

%ref.bc: %ref.c
	$(CLANG) $< -o $@ -c -emit-llvm -O0 -std=c90

clean:
	$(RM) xxhash32-ref.bc xxhash64-ref.bc

.PHONY: all clean prove
