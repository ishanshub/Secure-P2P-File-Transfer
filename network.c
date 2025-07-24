#include "peer.h"

// periodically broadcast user info 
void* broadcast_thread(void* arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int broadcastEnable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
    struct sockaddr_in broadcast_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(BROADCAST_PORT),
        .sin_addr.s_addr = inet_addr("255.255.255.255")
    };
    char message[100];
    while (1) {
        snprintf(message, sizeof(message), "%s %s %d", my_name, my_ip, my_port);
        sendto(sock, message, strlen(message), 0, (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        sleep(BROADCAST_INTERVAL);
    }
    close(sock);
    return NULL;
}

// listens for broadcast from other peers and updates peer list
void* listen_broadcast_thread(void* arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in recv_addr = { .sin_family = AF_INET, .sin_port = htons(BROADCAST_PORT), .sin_addr.s_addr = INADDR_ANY };
    bind(sock, (struct sockaddr*)&recv_addr, sizeof(recv_addr));
    while (1) {
        char buffer[100];
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        int len = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&sender_addr, &addr_len);
        if (len <= 0) continue;
        buffer[len] = '\0';
        char peer_name[50], peer_ip[INET_ADDRSTRLEN];
        int peer_port;
        if (sscanf(buffer, "%49s %15s %d", peer_name, peer_ip, &peer_port) != 3) continue;
        if (strcmp(peer_name, my_name) == 0) continue;
        pthread_mutex_lock(&peer_list_mutex);
        int found = 0;
        for (int i = 0; i < peer_count; i++) {
            if (strcmp(peers[i].name, peer_name) == 0) {
                peers[i].last_seen = time(NULL);
                found = 1;
                break;
            }
        }
        if (!found && peer_count < MAX_PEERS) {
            strncpy(peers[peer_count].name, peer_name, sizeof(peers[0].name)-1);
            peers[peer_count].name[sizeof(peers[0].name)-1] = '\0';
            strncpy(peers[peer_count].ip, peer_ip, sizeof(peers[0].ip)-1);
            peers[peer_count].ip[sizeof(peers[0].ip)-1] = '\0';
            peers[peer_count].port = peer_port;
            peers[peer_count].last_seen = time(NULL);
            peer_count++;
            printf("\n[PEER] Discovered new peer: %s at %s:%d\n", peer_name, peer_ip, peer_port);
            printf("Choice: "); fflush(stdout);
        }
        pthread_mutex_unlock(&peer_list_mutex);
    }
    close(sock);
    return NULL;
}

// remove peers from peer list which are inactive
void* cleanup_peers_thread(void* arg) {
    while (1) {
        sleep(PEER_TIMEOUT_SECONDS);
        time_t now = time(NULL);
        pthread_mutex_lock(&peer_list_mutex);
        for (int i = 0; i < peer_count; ) {
            if (difftime(now, peers[i].last_seen) > PEER_TIMEOUT_SECONDS) {
                printf("\n[PEER] Peer %s (%s:%d) timed out. Removing from list.\n", peers[i].name, peers[i].ip, peers[i].port);
                printf("Choice: "); fflush(stdout);
                for (int j = i; j < peer_count - 1; j++) {
                    peers[j] = peers[j + 1];
                }
                peer_count--;
            } else {
                i++;
            }
        }
        pthread_mutex_unlock(&peer_list_mutex);
    }
    return NULL;
}
