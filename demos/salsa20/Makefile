all: salsa20.bc salsa20.saw
	saw salsa20.saw

salsa20.c: salsa20.h

%.bc: %.c
	clang -c -g -emit-llvm $<

clean:
	rm -f salsa20.bc
