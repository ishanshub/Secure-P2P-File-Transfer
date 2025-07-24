#include "peer.h"

// 
Peer peers[MAX_PEERS];
int peer_count = 0;
char my_name[50];
char my_ip[INET_ADDRSTRLEN];
int my_port;
pthread_mutex_t peer_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void clear_stdin(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int main(void) {
    printf("Secure P2P File Transfer\n\n");

    mkdir(SHARED_DIR, 0755);
    printf("[INFO] Shared directory is './%s'\n", SHARED_DIR);
    printf("[INFO] Place files you want to share in this directory.\n");

    printf("\nEnter your name (no spaces): ");
    if (scanf("%49s", my_name) != 1) {
        fprintf(stderr, "Invalid input\n");
        return EXIT_FAILURE;
    }
    clear_stdin();

    printf("Enter your port number: ");
    if (scanf("%d", &my_port) != 1 || my_port < 1024 || my_port > 65535) {
        fprintf(stderr, "Invalid port number\n");
        return EXIT_FAILURE;
    }
    clear_stdin();

    FILE *fp = popen("hostname -I | awk '{print $1}'", "r");
    if (!fp || fscanf(fp, "%15s", my_ip) != 1) {
        strcpy(my_ip, "127.0.0.1");
        printf("[WARN] Could not detect IP. Default set to %s.\n", my_ip);
    }
    pclose(fp);

    printf("[INFO] Your name: %s\n", my_name);
    printf("[INFO] Your IP: %s\n", my_ip);

    pthread_t threads[4];
    pthread_create(&threads[0], NULL, server_thread, NULL);
    pthread_create(&threads[1], NULL, broadcast_thread, NULL);
    pthread_create(&threads[2], NULL, listen_broadcast_thread, NULL);
    pthread_create(&threads[3], NULL, cleanup_peers_thread, NULL);

    while (1) {
        printf("\n--- Main Menu ---\n");
        printf("1. Show peer list\n");
        printf("2. Browse and download\n");
        printf("3. Exit\n");
        printf("Choice: ");

        int choice;
        if (scanf("%d", &choice) != 1) {
            clear_stdin();
            continue;
        }
        clear_stdin();

        switch (choice) {
            case 1:
                refresh_peers();
                break;
            case 2:
                browse_and_request_files();
                break;
            case 3:
                printf("[INFO] Exiting...\n");
                exit(EXIT_SUCCESS);
            default:
                printf("[ERROR] Invalid choice.\n");
        }
    }

    return 0;
}
