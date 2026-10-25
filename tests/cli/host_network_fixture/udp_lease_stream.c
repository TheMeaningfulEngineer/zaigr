#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static volatile sig_atomic_t stopping_sends;

static void stop_stream(int signal_number) {
    if (signal_number == SIGUSR1) {
        stopping_sends = 1;
    } else {
        stopping = 1;
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s HOST PORT LOCAL_PORT\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    long remote_port = strtol(argv[2], &end, 10);
    if (*end != '\0' || remote_port < 1 || remote_port > 65535) return 2;
    long local_port = strtol(argv[3], &end, 10);
    if (*end != '\0' || local_port < 1 || local_port > 65535) return 2;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons((uint16_t)local_port)};
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) return 1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return 1;

    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((uint16_t)remote_port)};
    if (inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1) return 2;
    signal(SIGTERM, stop_stream);
    signal(SIGINT, stop_stream);
    signal(SIGUSR1, stop_stream);

    uint64_t sent = 0;
    uint64_t received = 0;
    time_t next_report = time(NULL);
    struct timespec next_send;
    clock_gettime(CLOCK_MONOTONIC, &next_send);
    struct timespec last_receive = next_send;
    while (!stopping) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (!stopping_sends && (now.tv_sec > next_send.tv_sec ||
                (now.tv_sec == next_send.tv_sec && now.tv_nsec >= next_send.tv_nsec))) {
            char payload[64];
            int length = snprintf(payload, sizeof(payload), "GUEST:%llu", (unsigned long long)sent);
            if (sendto(fd, payload, (size_t)length, 0, (struct sockaddr *)&peer, sizeof(peer)) >= 0) {
                sent++;
            }
            next_send.tv_nsec += 20000000;
            if (next_send.tv_nsec >= 1000000000) {
                next_send.tv_sec++;
                next_send.tv_nsec -= 1000000000;
            }
        }
        char reply[256];
        ssize_t size = recvfrom(fd, reply, sizeof(reply), 0, NULL, NULL);
        if (size >= 6 && memcmp(reply, "HOST:", 5) == 0) {
            int valid_sequence = 1;
            for (ssize_t index = 5; index < size; index++) {
                if (reply[index] < '0' || reply[index] > '9') valid_sequence = 0;
            }
            if (valid_sequence) received++;
            clock_gettime(CLOCK_MONOTONIC, &last_receive);
        } else if (size < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            perror("recvfrom");
            break;
        }
        if (stopping_sends && size < 0) {
            struct timespec quiet_now;
            clock_gettime(CLOCK_MONOTONIC, &quiet_now);
            if (quiet_now.tv_sec - last_receive.tv_sec > 0 ||
                    (quiet_now.tv_sec == last_receive.tv_sec &&
                     quiet_now.tv_nsec - last_receive.tv_nsec >= 300000000)) {
                break;
            }
        }
        if (time(NULL) >= next_report) {
            printf("GUEST_SENT=%llu GUEST_RECEIVED=%llu\n",
                   (unsigned long long)sent, (unsigned long long)received);
            fflush(stdout);
            next_report = time(NULL) + 1;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
    printf("GUEST_SENT=%llu GUEST_RECEIVED=%llu\n",
           (unsigned long long)sent, (unsigned long long)received);
    printf("GUEST_STREAM_DRAINED=1\n");
    fflush(stdout);
    close(fd);
    return 0;
}
