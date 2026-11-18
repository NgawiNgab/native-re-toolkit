#include <stdint.h>
#include <stdio.h>

/* Well-known crypto constants for signature-scan ground truth. */

__attribute__((used)) static const uint32_t sha256_k[8] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
};

__attribute__((used)) static const uint8_t aes_sbox[32] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
};

__attribute__((used)) static const uint32_t md5_k[8] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
};

__attribute__((used)) static const uint32_t crc32_tab[8] = {
    0x00000000u, 0x77073096u, 0xee0e612cu, 0x990951bau,
    0x076dc419u, 0x706af48fu, 0xe963a535u, 0x9e6495a3u,
};

__attribute__((used)) static const char chacha_sigma[16] = "expand 32-byte k";

__attribute__((used)) static const char b64_alpha[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main(void) {
    /* reference the tables so the linker keeps them */
    uint32_t acc = sha256_k[0] ^ md5_k[0] ^ crc32_tab[1] ^ aes_sbox[0];
    printf("acc=%u %c%c\n", acc, chacha_sigma[0], b64_alpha[0]);
    return 0;
}
