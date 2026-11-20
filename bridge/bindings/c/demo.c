/* CipherBird C-ABI reference demo. Exercises hashing, the vault, and the keyring
 * (envelope/key-slots) end to end. Built natively, and also run on the iOS
 * simulator and Android emulator to verify the ABI on every native platform.
 *
 * Native build (see Makefile / verify script):
 *   cc bridge/c/demo.c -Ibridge -Lbuild/release -lcipherbird_c \
 *      -Wl,-rpath,build/release -o build/c_demo && ./build/c_demo
 */
#include "cipherbird_c.h"
#include <stdio.h>
#include <string.h>

static int bufeq(const CryptoBuffer* a, const CryptoBuffer* b) {
    return a->len == b->len && a->data && b->data && memcmp(a->data, b->data, a->len) == 0;
}

int main(void) {
    if (cipherbird_init() != 0) { printf("FAIL init\n"); return 1; }
    printf("version %s\n", cipherbird_version());

    /* SHA-256("abc") known answer */
    unsigned char abc[3] = { 'a', 'b', 'c' };
    CryptoBufferResult h = cipherbird_sha256(abc, 3);
    printf("sha256 ");
    for (size_t i = 0; i < h.buf.len; ++i) printf("%02x", h.buf.data[i]);
    printf("\n");
    cipherbird_buffer_free(&h.buf);

    /* Vault seal -> open */
    CryptoBufferResult key = cipherbird_random_bytes(32);
    CryptoVaultHandle vault = cipherbird_vault_create(key.buf.data, key.buf.len, 0);
    cipherbird_buffer_free(&key.buf);
    char* verr = NULL;
    const char* msg = "c abi";
    CryptoPacket pkt = cipherbird_vault_seal(vault, (const unsigned char*)msg, strlen(msg), "ctx", &verr);
    if (verr) { printf("FAIL seal %s\n", verr); return 1; }
    CryptoBufferResult opened = cipherbird_vault_open(vault, &pkt, "ctx");
    printf("vault roundtrip %.*s\n", (int)opened.buf.len, (char*)opened.buf.data);
    cipherbird_buffer_free(&opened.buf);
    cipherbird_packet_free(&pkt);
    cipherbird_vault_free(vault);

    /* ── Keyring: 1 device slot (default) + 1 passphrase slot (cross-device) ── */
    unsigned char factor[32];
    CryptoBufferResult fr = cipherbird_random_bytes(32);
    memcpy(factor, fr.buf.data, 32);
    cipherbird_buffer_free(&fr.buf);

    CryptoKeyringHandle kr = cipherbird_keyring_create();
    if (!kr) { printf("FAIL keyring create\n"); return 1; }
    if (!cipherbird_keyring_add_device_slot(kr, factor, 32)) { printf("FAIL add device\n"); return 1; }
    if (!cipherbird_keyring_add_passphrase_slot(kr, "correct horse", 0)) { printf("FAIL add pass\n"); return 1; }
    printf("keyring slots %zu\n", cipherbird_keyring_slot_count(kr));

    CryptoBufferResult blob = cipherbird_keyring_serialise(kr);
    if (!blob.buf.data) { printf("FAIL serialise\n"); return 1; }

    char* kerr = NULL;
    CryptoKeyringHandle kr2 = cipherbird_keyring_deserialise(blob.buf.data, blob.buf.len, &kerr);
    if (!kr2) { printf("FAIL deserialise %s\n", kerr ? kerr : ""); return 1; }

    CryptoBufferResult md = cipherbird_keyring_unlock_with_device(kr2, factor, 32);
    CryptoBufferResult mp = cipherbird_keyring_unlock_with_passphrase(kr2, "correct horse");
    if (!md.buf.data || !mp.buf.data) { printf("FAIL keyring unlock\n"); return 1; }
    printf("keyring device==passphrase master: %s\n", bufeq(&md.buf, &mp.buf) ? "yes" : "NO");

    /* Wrong factor must fail */
    unsigned char wrong[32] = {0};
    CryptoBufferResult bad = cipherbird_keyring_unlock_with_device(kr2, wrong, 32);
    printf("keyring wrong-factor rejected: %s\n", bad.buf.data ? "NO" : "yes");
    if (bad.error) cipherbird_str_free(bad.error);

    cipherbird_buffer_free(&md.buf);
    cipherbird_buffer_free(&mp.buf);
    cipherbird_buffer_free(&blob.buf);
    cipherbird_keyring_free(kr);
    cipherbird_keyring_free(kr2);

    printf("C demo OK\n");
    return 0;
}
