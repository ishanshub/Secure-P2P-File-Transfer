#ifndef PEER_H
#define PEER_H

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

// --- Configuration & Constants ---
#define MAX_PEERS 10
#define BUFFER_SIZE 8192
#define BROADCAST_PORT 9090
#define BROADCAST_INTERVAL 5
#define PEER_TIMEOUT_SECONDS 15
#define SHARED_DIR "shared"

// --- Protocol Message Types ---
#define MSG_TYPE_LIST_REQUEST 'L'
#define MSG_TYPE_FILE_REQUEST 'R'
#define MSG_TYPE_ERROR 'E'
#define MSG_TYPE_END_OF_LIST 'F'

// --- Data Structures ---
typedef struct {
    char name[50];
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t last_seen;
} Peer;

// --- Global Variables (declared as extern) ---
// The actual definition will be in main.c
extern Peer peers[MAX_PEERS];
extern int peer_count;
extern char my_name[50];
extern char my_ip[INET_ADDRSTRLEN];
extern int my_port;
extern pthread_mutex_t peer_list_mutex;

// --- Function Prototypes ---

// crypto.c
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, int *ciphertext_len);
void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, int *plaintext_len);
void generate_hmac(unsigned char *data, int data_len, unsigned char *key, unsigned char *hmac_output);
int do_diffie_hellman(int sock, unsigned char* derived_key);

// network.c
void* broadcast_thread(void* arg);
void* listen_broadcast_thread(void* arg);
void* cleanup_peers_thread(void* arg);

// server.c
void* server_thread(void* arg);
void handle_list_request(int sock, unsigned char* key);
void handle_file_request(int sock, unsigned char* key);
int is_path_safe(const char* filename, char* full_path);

// client.c
void refresh_peers(void);
void browse_and_request_files(void);

// main.c
void clear_stdin(void);

#endif // PEER_H
