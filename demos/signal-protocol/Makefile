LIBSIGNAL_DIR=libsignal-protocol-c
LIBSIGNAL_BUILD_DIR=$(LIBSIGNAL_DIR)/build
LLVM_LINK_NAME=$(shell dirname $(shell readlink -f $(shell which clang)))/llvm-link

.PHONY: all
all: all-saw-script

.PHONY: all-saw-script
all-saw-script: libsignal
	saw saw/main.saw

.PHONY: all-python
all-python: libsignal
	poetry install
	poetry run mypy python/main.py
	poetry run python python/main.py

libsignal: c/libsignal-everything.bc

$(LIBSIGNAL_BUILD_DIR)/src/libsignal-protocol-c.a:
	mkdir -p $(LIBSIGNAL_BUILD_DIR)
	(cd $(LIBSIGNAL_BUILD_DIR) && \
	LLVM_COMPILER=clang cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=wllvm .. && \
	LLVM_COMPILER=clang make)

$(LIBSIGNAL_BUILD_DIR)/src/libsignal-protocol-c.a.bc: $(LIBSIGNAL_BUILD_DIR)/src/libsignal-protocol-c.a
	(cd $(LIBSIGNAL_BUILD_DIR) && \
	extract-bc -l $(LLVM_LINK_NAME) -b src/libsignal-protocol-c.a)

c/libsignal-everything.bc: $(LIBSIGNAL_BUILD_DIR)/src/libsignal-protocol-c.a.bc c/dummy_signal_crypto_provider.bc
	$(LLVM_LINK_NAME) $^ -o $@

c/dummy_signal_crypto_provider.bc: c/dummy_signal_crypto_provider.c
	clang -g -c -emit-llvm $< -o $@ -I$(LIBSIGNAL_DIR)/src

.PHONY: clean
clean:
	rm -rf $(LIBSIGNAL_BUILD_DIR) c/dummy_signal_crypto_provider.bc
