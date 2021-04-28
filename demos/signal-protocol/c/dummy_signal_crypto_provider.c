#include <stdint.h>
#include <stdlib.h>

#include "signal_protocol_internal.h"

// Definition taken from
// https://github.com/signalapp/libsignal-protocol-c/blob/3a83a4f4ed2302ff6e68ab569c88793b50c22d28/src/protocol.c#L10
#define SIGNAL_MESSAGE_MAC_LENGTH 8

// Type signatures taken from
// https://github.com/signalapp/libsignal-protocol-c/blob/3a83a4f4ed2302ff6e68ab569c88793b50c22d28/src/signal_protocol.h#L276
int dummy_random_func(uint8_t *data, size_t len, void *user_data) {
    return 0;
}

int dummy_hmac_sha256_init_func(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data) {
    uint8_t *dummy_hmac_context = malloc(sizeof(uint8_t));
    if (dummy_hmac_context == NULL) {
        return -1;
    }
    *dummy_hmac_context = 42;
    *hmac_context = dummy_hmac_context;
    return 0;
}

int dummy_hmac_sha256_update_func(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data) {
    return 0;
}

int dummy_hmac_sha256_final_func(void *hmac_context, signal_buffer **output, void *user_data) {
    *output = signal_buffer_alloc(SIGNAL_MESSAGE_MAC_LENGTH);
    if (*output == NULL) {
        return -1;
    } else {
        return 0;
    }
}

void dummy_hmac_sha256_cleanup_func(void *hmac_context, void *user_data) {
    free(hmac_context);
}

int dummy_sha512_digest_init_func(void **digest_context, void *user_data) {
    uint8_t *dummy_digest_context = malloc(sizeof(uint8_t));
    if (dummy_digest_context == NULL) {
        return -1;
    }
    *dummy_digest_context = 42;
    *digest_context = digest_context;
    return 0;
}

int dummy_sha512_digest_update_func(void *digest_context, const uint8_t *data, size_t data_len, void *user_data) {
    return 0;
}

int dummy_sha512_digest_final_func(void *digest_context, signal_buffer **output, void *user_data) {
    *output = signal_buffer_alloc(SIGNAL_MESSAGE_MAC_LENGTH);
    if (*output == NULL) {
        return -1;
    } else {
        return 0;
    }
}

void dummy_sha512_digest_cleanup_func(void *digest_context, void *user_data) {
    free(digest_context);
}

int dummy_encrypt_func(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data) {
    return 0;
}

int dummy_decrypt_func(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data) {
    return 0;
}
