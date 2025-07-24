#include "peer.h"

// encrypt
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
             unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext + sizeof(iv), &len, plaintext, plaintext_len);
    *ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + sizeof(iv) + len, &len);
    *ciphertext_len += len;
    memcpy(ciphertext, iv, sizeof(iv));
    *ciphertext_len += sizeof(iv);
    EVP_CIPHER_CTX_free(ctx);
}

// decrypt
void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
             unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    memcpy(iv, ciphertext, sizeof(iv));
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    int len;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + sizeof(iv), ciphertext_len - sizeof(iv));
    *plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

// hmac
void generate_hmac(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *hmac_output) {
    unsigned int len;
    HMAC(EVP_sha256(), key, 16, data, data_len, hmac_output, &len);
}

// DH
int do_diffie_hellman(int sock, unsigned char* derived_key) {
    DH* dh = DH_get_2048_256();
    if (!dh || !DH_generate_key(dh)) {
        perror("DH key generation failed");
        return -1;
    }

    const BIGNUM *pub_key;
    DH_get0_key(dh, &pub_key, NULL);

    int pub_key_len = BN_num_bytes(pub_key);
    unsigned char* pub_key_bin = malloc(pub_key_len);
    BN_bn2bin(pub_key, pub_key_bin);

    if (send(sock, &pub_key_len, sizeof(int), 0) < 0 ||
        send(sock, pub_key_bin, pub_key_len, 0) < 0) {
        perror("DH key send failed");
        free(pub_key_bin); DH_free(dh); return -1;
    }

    int peer_pub_key_len;
    if (recv(sock, &peer_pub_key_len, sizeof(int), 0) <= 0) {
        perror("DH key length receive failed");
        free(pub_key_bin); DH_free(dh); return -1;
    }

    unsigned char* peer_pub_key_bin = malloc(peer_pub_key_len);
    if (recv(sock, peer_pub_key_bin, peer_pub_key_len, 0) <= 0) {
        perror("DH key receive failed");
        free(pub_key_bin); free(peer_pub_key_bin); DH_free(dh); return -1;
    }

    BIGNUM* peer_pub_key = BN_bin2bn(peer_pub_key_bin, peer_pub_key_len, NULL);
    unsigned char shared_secret[256];
    int secret_size = DH_compute_key(shared_secret, peer_pub_key, dh);

    if (secret_size <= 0) {
        printf("[ERROR] DH key computation failed.\n");
        free(pub_key_bin); free(peer_pub_key_bin); BN_free(peer_pub_key); DH_free(dh);
        return -1;
    }

    memcpy(derived_key, shared_secret, 16);

    free(pub_key_bin);
    free(peer_pub_key_bin);
    BN_free(peer_pub_key);
    DH_free(dh);
    return 0;
}
