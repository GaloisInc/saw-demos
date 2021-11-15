LLVM_CONFIG ?= llvm-config
LLVM_BIN_DIR = $(shell $(LLVM_CONFIG) --bindir)
CLANG=$(LLVM_BIN_DIR)/clang


all: salsa20.bc salsa20.saw
	saw salsa20.saw

salsa20.c: salsa20.h

%.bc: %.c
	$(CLANG) -c -g -emit-llvm $<

clean:
	rm -f salsa20.bc
