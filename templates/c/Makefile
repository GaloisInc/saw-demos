all: dotprod.bc dotprod.saw
	saw dotprod.saw

%.bc: %.c
	clang -c -g -emit-llvm $<

clean:
	rm -f dotprod.bc
