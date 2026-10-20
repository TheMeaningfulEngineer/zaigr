#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int write_all(int fd, const char *data, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, data, length);
        if (written <= 0) {
            return -1;
        }
        data += written;
        length -= (size_t)written;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s IPv4 PORT PATH\n", argv[0]);
        return 2;
    }

    int port = atoi(argv[2]);
    if (port < 1 || port > 65535) {
        fprintf(stderr, "invalid port\n");
        return 2;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    int receive_buffer = 4096;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)) != 0) {
        perror("setsockopt(SO_RCVBUF)");
        close(fd);
        return 1;
    }
#ifdef TCP_WINDOW_CLAMP
    int window_clamp = 4096;
    if (setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &window_clamp, sizeof(window_clamp)) != 0) {
        perror("setsockopt(TCP_WINDOW_CLAMP)");
        close(fd);
        return 1;
    }
#endif

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) {
        fprintf(stderr, "invalid IPv4 address\n");
        close(fd);
        return 2;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    char request[2048];
    int request_length = snprintf(
        request, sizeof(request),
        "GET %s HTTP/1.1\r\nHost: deb.debian.org\r\nConnection: close\r\n\r\n",
        argv[3]
    );
    if (request_length < 0 || (size_t)request_length >= sizeof(request)
            || write_all(fd, request, (size_t)request_length) != 0) {
        perror("write HTTP request");
        close(fd);
        return 1;
    }

    char buffer[1024];
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received == 0) {
            break;
        }
        if (received < 0) {
            perror("recv");
            close(fd);
            return 1;
        }
        if (fwrite(buffer, 1, (size_t)received, stdout) != (size_t)received
                || fflush(stdout) != 0) {
            perror("write stream output");
            close(fd);
            return 1;
        }
        usleep(10000);
    }
    close(fd);
    return 0;
}
