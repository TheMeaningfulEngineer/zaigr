#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int interactive = argc == 4 && strcmp(argv[1], "--interactive") == 0;
    if ((!interactive && argc != 3) || (interactive && argc != 4)) {
        fprintf(stderr, "usage: udp_probe IPv4 PORT | udp_probe --interactive IPv4 PORT\n");
        return 2;
    }
    const char *address = interactive ? argv[2] : argv[1];
    const char *port = interactive ? argv[3] : argv[2];
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(port))};
    if (inet_pton(AF_INET, address, &peer.sin_addr) != 1) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (interactive) {
        struct timeval interactive_timeout = {.tv_sec = 0, .tv_usec = 300000};
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                       &interactive_timeout, sizeof(interactive_timeout)) < 0) {
            perror("setsockopt"); close(fd); return 1;
        }
        char request[1024];
        puts("UDP_PROBE_READY");
        fflush(stdout);
        while (fgets(request, sizeof(request), stdin) != NULL) {
            size_t length = strcspn(request, "\r\n");
            request[length] = '\0';
            if (strncmp(request, "BURST:", 6) == 0) {
                const char *payload = request + 6;
                for (int attempt = 0; attempt < 16; attempt++) {
                    if (sendto(fd, payload, strlen(payload), 0,
                               (struct sockaddr *)&peer, sizeof(peer)) < 0) {
                        perror("sendto"); close(fd); return 1;
                    }
                }
                puts("UDP_BURST_SENT=16");
                fflush(stdout);
                continue;
            }
            if (sendto(fd, request, length, 0,
                       (struct sockaddr *)&peer, sizeof(peer)) < 0) {
                perror("sendto"); close(fd); return 1;
            }
            char response[256] = {0};
            ssize_t received = recvfrom(fd, response, sizeof(response) - 1, 0, NULL, NULL);
            if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                puts("UDP_RESULT=DENIED");
            } else if (received < 0) {
                perror("recvfrom"); close(fd); return 1;
            } else {
                response[received] = '\0';
                printf("UDP_RESULT=%s", response);
            }
            fflush(stdout);
        }
        close(fd);
        return 0;
    }
    if (sendto(fd, "probe", 5, 0, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
        perror("sendto"); close(fd); return 1;
    }
    char response[256] = {0};
    ssize_t received = recvfrom(fd, response, sizeof(response) - 1, 0, NULL, NULL);
    if (received < 0) { puts("PROBE_RESULT=DENIED"); close(fd); return 0; }
    response[received] = '\0';
    printf("PROBE_RESULT=%s", response);
    close(fd);
    return 0;
}
