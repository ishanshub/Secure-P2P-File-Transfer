#include "peer.h"

// print peers
void refresh_peers(void) {
    pthread_mutex_lock(&peer_list_mutex);
    printf("\n--- Available Peers ---\n");
    if (peer_count == 0) {
        printf("No active peers found.\n");
    } else {
        for (int i = 0; i < peer_count; i++) {
            printf("%d. %s (%s:%d)\n", i+1, peers[i].name, peers[i].ip, peers[i].port);
        }
    }
    printf("-----------------------\n");
    pthread_mutex_unlock(&peer_list_mutex);
}

// get file list and choose a file to download
void browse_and_request_files(void) {
    refresh_peers();
    if (peer_count == 0) return;
    printf("Enter peer number to browse: ");
    int choice;
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > peer_count) {
        printf("[ERROR] Invalid choice.\n");
        while (getchar() != '\n');
        return;
    }
    Peer p;
    pthread_mutex_lock(&peer_list_mutex);
    p = peers[choice-1];
    pthread_mutex_unlock(&peer_list_mutex);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in peer_addr = { .sin_family = AF_INET, .sin_port = htons(p.port), .sin_addr.s_addr = inet_addr(p.ip) };
    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }
    printf("[CLIENT] Connected to %s. Performing key exchange...\n", p.name);
    unsigned char derived_key[16];
    if (do_diffie_hellman(sock, derived_key) != 0) {
        close(sock);
        return;
    }
    printf("[CLIENT] Secure channel established.\n");
    char list_req = MSG_TYPE_LIST_REQUEST;
    send(sock, &list_req, sizeof(char), 0);
    printf("\n--- Files available from %s ---\n", p.name);
    char available_files[100][256];
    int file_count = 0;
    while(file_count < 100) {
        int encrypted_len;
        if (recv(sock, &encrypted_len, sizeof(int), 0) <= 0) break;
        unsigned char encrypted_data[BUFFER_SIZE];
        if (recv(sock, encrypted_data, encrypted_len, 0) <= 0) break;
        unsigned char decrypted_data[BUFFER_SIZE];
        int decrypted_len;
        decrypt(encrypted_data, encrypted_len, derived_key, decrypted_data, &decrypted_len);
        if (decrypted_len == 1 && decrypted_data[0] == MSG_TYPE_END_OF_LIST) {
            break;
        }
        decrypted_data[decrypted_len] = '\0';
        printf("%d. %s\n", file_count + 1, (char*)decrypted_data);
        strncpy(available_files[file_count], (char*)decrypted_data, 255);
        available_files[file_count][255] = '\0';
        file_count++;
    }
    close(sock);
    if (file_count == 0) {
        printf("No files available from this peer.\n");
        printf("---------------------------------\n");
        return;
    }
    printf("---------------------------------\n");
    printf("Enter file number to download (or 0 to cancel): ");
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > file_count) {
        printf("[INFO] Download cancelled.\n");
        while (getchar() != '\n');
        return;
    }
    char* chosen_file = available_files[choice-1];
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("Reconnect failed");
        return;
    }
    if (do_diffie_hellman(sock, derived_key) != 0) {
        close(sock);
        return;
    }
    char file_req = MSG_TYPE_FILE_REQUEST;
    send(sock, &file_req, sizeof(char), 0);
    unsigned char encrypted_fname[BUFFER_SIZE];
    int encrypted_fname_len;
    encrypt((unsigned char*)chosen_file, strlen(chosen_file), derived_key, encrypted_fname, &encrypted_fname_len);
    send(sock, &encrypted_fname_len, sizeof(int), 0);
    send(sock, encrypted_fname, encrypted_fname_len, 0);
    printf("[CLIENT] Requesting file '%s'...\n", chosen_file);
    int ciphertext_len;
    if (recv(sock, &ciphertext_len, sizeof(int), 0) <= 0) {
        printf("[ERROR] Failed to receive file data from peer.\n");
        close(sock);
        return;
    }
    if (ciphertext_len == 1) {
        char msg_type;
        recv(sock, &msg_type, 1, 0);
        if (msg_type == MSG_TYPE_ERROR) {
            printf("[ERROR] Peer reported an error (file not found or access denied).\n");
            close(sock);
            return;
        }
    }
    unsigned char* ciphertext = malloc(ciphertext_len);
    int bytes_received = 0;
    while(bytes_received < ciphertext_len) {
        int result = recv(sock, ciphertext + bytes_received, ciphertext_len - bytes_received, 0);
        if (result <= 0) {
            printf("[ERROR] File download interrupted.\n");
            free(ciphertext);
            close(sock);
            return;
        }
        bytes_received += result;
    }
    unsigned char received_hmac[32];
    recv(sock, received_hmac, 32, 0);
    unsigned char computed_hmac[32];
    generate_hmac(ciphertext, ciphertext_len, derived_key, computed_hmac);
    if (memcmp(received_hmac, computed_hmac, 32) != 0) {
        printf("[ERROR] HMAC verification FAILED! File is corrupted. Discarding.\n");
    } else {
        unsigned char* plaintext = malloc(ciphertext_len);
        int plaintext_len;
        decrypt(ciphertext, ciphertext_len, derived_key, plaintext, &plaintext_len);
        char save_path[PATH_MAX];
        snprintf(save_path, sizeof(save_path), "%s/%s", SHARED_DIR, chosen_file);
        FILE *fp = fopen(save_path, "wb");
        if (fp) {
            fwrite(plaintext, 1, plaintext_len, fp);
            fclose(fp);
            printf("[SUCCESS] File '%s' downloaded and verified successfully!\n", chosen_file);
            printf("Saved to: %s\n", save_path);
        }
        free(plaintext);
    }
    free(ciphertext);
    close(sock);
}
