/* Independent acceptance endpoint. No zaigr state or status logic lives here. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

static void die(const char *s) { perror(s); exit(1); }
static void write_all(int fd, const char *s, size_t n) {
    while (n) { ssize_t done = write(fd, s, n); if (done <= 0) die("write"); s += done; n -= done; }
}

static int control_watch(const char *path) {
    int file = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (file < 0) die("control file");
    if (fchmod(file, 0666)) die("control permissions");
    close(file);
    int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (fd < 0 || inotify_add_watch(fd, path, IN_CLOSE_WRITE) < 0) die("control watch");
    return fd;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    setbuf(stdout, NULL);
    alarm(480);
    if (!strcmp(argv[1], "watch")) {
        if (argc != 4) return 2;
        int fd = inotify_init1(IN_CLOEXEC);
        if (fd < 0 || inotify_add_watch(fd, argv[2], IN_OPEN | IN_CLOSE) < 0) die("inotify");
        int control = open(argv[3], O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (control < 0) die("control file");
        close(control);
        int boundary = inotify_add_watch(fd, argv[3], IN_CLOSE_WRITE);
        if (boundary < 0) die("boundary watch");
        unsigned syncs = 0;
        puts("READY");
        for (;;) {
            union { struct inotify_event align; char bytes[4096]; } buffer;
            ssize_t n = read(fd, buffer.bytes, sizeof(buffer.bytes));
            if (n <= 0) die("inotify read");
            for (char *p = buffer.bytes; p < buffer.bytes + n;) {
                struct inotify_event *e = (void *)p;
                if (e->wd == boundary) printf("SYNC %u\n", ++syncs);
                else {
                    if (e->mask & IN_OPEN) puts("OPEN");
                    if (e->mask & IN_CLOSE) puts("CLOSE");
                }
                p += sizeof(*e) + e->len;
            }
        }
    }
    if (!strcmp(argv[1], "netwatch")) {
        if (argc != 4) return 2;
        int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK, htons(ETH_P_IP));
        if (fd < 0) die("packet socket");
        struct pollfd ready[2] = {{.fd = fd, .events = POLLIN},
                                  {.fd = control_watch(argv[3]), .events = POLLIN}};
        unsigned syncs = 0;
        puts("READY");
        for (;;) {
            if (poll(ready, 2, -1) < 0) die("poll");
            // Drain all packets queued before acknowledging the control file.
            for (;;) {
            unsigned char bytes[65536];
            ssize_t n = read(fd, bytes, sizeof(bytes));
            if (n < 0) { if (errno == EAGAIN) break; die("packet read"); }
            if (n < (ssize_t)sizeof(struct iphdr)) continue;
            struct iphdr *ip = (void *)bytes;
            size_t header = ip->ihl * 4;
            if (ip->version != 4 || ip->protocol != IPPROTO_TCP || header < sizeof(*ip) ||
                n < (ssize_t)(header + sizeof(struct tcphdr))) continue;
            struct tcphdr *tcp = (void *)(bytes + header);
            if (tcp->syn && !tcp->ack && ntohs(tcp->dest) == atoi(argv[2])) puts("SYN");
            }
            if (ready[1].revents & POLLIN) {
                char events[4096];
                if (read(ready[1].fd, events, sizeof(events)) <= 0) die("control read");
                printf("SYNC %u\n", ++syncs);
            }
        }
    }
    if (!strcmp(argv[1], "device")) {
        if (argc != 4) return 2;
        int fd = open(argv[2], O_RDWR | O_NOCTTY);
        if (fd < 0) die("device open");
        struct termios settings;
        if (tcgetattr(fd, &settings)) die("tcgetattr");
        cfmakeraw(&settings);
        cfsetispeed(&settings, B19200); cfsetospeed(&settings, B19200);
        if (tcsetattr(fd, TCSANOW, &settings)) die("tcsetattr");
        puts("READY");
        char payload[256]; size_t used = 0;
        while (used < sizeof(payload)) {
            ssize_t n = read(fd, payload + used, sizeof(payload) - used);
            if (n <= 0) die("device read");
            used += n;
            if (payload[used - 1] == '\n') break;
        }
        char path[1024];
        snprintf(path, sizeof(path), "%s.received", argv[3]);
        int output = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (output < 0) die("received file");
        write_all(output, payload, used); close(output);
        write_all(fd, argv[3], strlen(argv[3])); write_all(fd, "\n", 1);
        snprintf(path, sizeof(path), "%s.release", argv[3]);
        while (access(path, F_OK)) usleep(10000);
        close(fd); puts("CLOSED"); return 0;
    }
    if (strcmp(argv[1], "server") || argc != 5) return 2;
    int family = strchr(argv[2], ':') ? AF_INET6 : AF_INET;
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) die("setsockopt");
    if (family == AF_INET6) {
        struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(atoi(argv[3]))};
        int only = 0;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only))) die("dual stack");
        if (inet_pton(family, argv[2], &address.sin6_addr) != 1) return 2;
        if (bind(fd, (void *)&address, sizeof(address))) die("bind");
    } else {
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[3]))};
        if (inet_pton(family, argv[2], &address.sin_addr) != 1) return 2;
        if (bind(fd, (void *)&address, sizeof(address))) die("bind");
    }
    if (listen(fd, 8)) die("listen");
    puts("READY");
    for (;;) {
        int peer = accept(fd, NULL, NULL);
        if (peer < 0) die("accept");
        puts("ACCEPTED");
        char request[4096];
        if (read(peer, request, sizeof(request)) > 0) {
            const char *header = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n";
            write_all(peer, header, strlen(header)); write_all(peer, argv[4], strlen(argv[4]));
        }
        close(peer);
    }
}
