LLVM_CONFIG ?= llvm-config
CLANG=$(shell $(LLVM_CONFIG) --bindir)/clang

all: dotprod.bc dotprod.saw
	saw dotprod.saw

%.bc: %.c
	$(CLANG) -c -g -emit-llvm $<

clean:
	rm -f dotprod.bc
