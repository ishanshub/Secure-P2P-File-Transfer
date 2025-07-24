#include "peer.h"

int is_path_safe(const char* filename, char* full_path) {
    if (strstr(filename, "..") != NULL) {
        printf("[SECURITY] Path traversal attempt rejected: '%s'\n", filename);
        return -1;
    }
    char real_shared_path[PATH_MAX];
    if (realpath(SHARED_DIR, real_shared_path) == NULL) {
        perror("Could not resolve real path of shared directory");
        return -1;
    }
    if (strlen(real_shared_path) + strlen(filename) + 2 > PATH_MAX) {
        printf("[SECURITY] Resulting path is too long.\n");
        return -1;
    }
    snprintf(full_path, PATH_MAX, "%s/%s", real_shared_path, filename);
    char real_requested_path[PATH_MAX];
    if (realpath(full_path, real_requested_path) != NULL) {
        if (strncmp(real_shared_path, real_requested_path, strlen(real_shared_path)) != 0) {
            printf("[SECURITY] Path traversal attempt rejected: '%s' resolves outside shared directory.\n", filename);
            return -1;
        }
    } else {
        if (strncmp(real_shared_path, full_path, strlen(real_shared_path)) != 0) {
            return -1;
        }
    }
    return 0;
}

void handle_list_request(int sock, unsigned char* key) {
    printf("[SERVER] Received request for file list.\n");
    DIR *d = opendir(SHARED_DIR);
    if (!d) {
        printf("[SERVER-ERROR] Could not open shared directory '%s'.\n", SHARED_DIR);
        char end_marker = MSG_TYPE_END_OF_LIST;
        send(sock, &end_marker, sizeof(char), 0);
        return;
    }
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {
            unsigned char ciphertext[BUFFER_SIZE];
            int ciphertext_len;
            encrypt((unsigned char*)dir->d_name, strlen(dir->d_name), key, ciphertext, &ciphertext_len);
            if (send(sock, &ciphertext_len, sizeof(int), 0) < 0 ||
                send(sock, ciphertext, ciphertext_len, 0) < 0) {
                perror("Failed to send filename");
                break;
            }
        }
    }
    closedir(d);
    char end_marker = MSG_TYPE_END_OF_LIST;
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len;
    encrypt((unsigned char*)&end_marker, sizeof(char), key, ciphertext, &ciphertext_len);
    if (send(sock, &ciphertext_len, sizeof(int), 0) < 0 ||
        send(sock, ciphertext, ciphertext_len, 0) < 0) {
        perror("Failed to send end-of-list marker");
    }
}

void handle_file_request(int sock, unsigned char* key) {
    int encrypted_fname_len;
    if (recv(sock, &encrypted_fname_len, sizeof(int), 0) <= 0) return;
    unsigned char encrypted_fname[BUFFER_SIZE];
    if (recv(sock, encrypted_fname, encrypted_fname_len, 0) <= 0) return;
    char filename[256];
    int filename_len;
    decrypt(encrypted_fname, encrypted_fname_len, key, (unsigned char*)filename, &filename_len);
    filename[filename_len] = '\0';
    printf("[SERVER] Received request for file: '%s'\n", filename);
    char full_path[PATH_MAX];
    if (is_path_safe(filename, full_path) != 0) {
        char error_msg_type = MSG_TYPE_ERROR;
        send(sock, &error_msg_type, sizeof(char), 0);
        return;
    }
    FILE *fp = fopen(full_path, "rb");
    if (!fp) {
        printf("[SERVER-ERROR] File '%s' not found.\n", filename);
        char error_msg_type = MSG_TYPE_ERROR;
        send(sock, &error_msg_type, sizeof(char), 0);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *file_data = malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);
    unsigned char* ciphertext = malloc(file_size + 100);
    int ciphertext_len;
    encrypt(file_data, file_size, key, ciphertext, &ciphertext_len);
    unsigned char hmac[32];
    generate_hmac(ciphertext, ciphertext_len, key, hmac);
    if (send(sock, &ciphertext_len, sizeof(int), 0) < 0 ||
        send(sock, ciphertext, ciphertext_len, 0) < 0 ||
        send(sock, hmac, 32, 0) < 0) {
        perror("File send failed");
    } else {
        printf("[SERVER] Sent file '%s' successfully.\n", filename);
    }
    free(file_data);
    free(ciphertext);
}

void* server_thread(void* arg) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = { .sin_family = AF_INET, .sin_port = htons(my_port), .sin_addr.s_addr = INADDR_ANY };
    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);
    printf("[INFO] Server started. Listening for connections on port %d.\n", my_port);
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) continue;
        printf("\n[SERVER] Incoming connection from %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        printf("Choice: "); fflush(stdout);
        unsigned char derived_key[16];
        if (do_diffie_hellman(client_sock, derived_key) != 0) {
            close(client_sock);
            continue;
        }
        char request_type;
        if (recv(client_sock, &request_type, sizeof(char), 0) <= 0) {
            close(client_sock);
            continue;
        }
        switch(request_type) {
            case MSG_TYPE_LIST_REQUEST:
                handle_list_request(client_sock, derived_key);
                break;
            case MSG_TYPE_FILE_REQUEST:
                handle_file_request(client_sock, derived_key);
                break;
            default:
                printf("[SERVER-ERROR] Unknown request type from client.\n");
        }
        close(client_sock);
    }
    close(server_sock);
    return NULL;
}
