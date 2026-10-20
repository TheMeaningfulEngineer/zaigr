#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int send_all(int fd, const unsigned char *data, size_t length) {
    while (length > 0) {
        ssize_t sent = send(fd, data, length, 0);
        if (sent <= 0) return -1;
        data += sent;
        length -= (size_t)sent;
    }
    return 0;
}

static int recv_all(int fd, unsigned char *data, size_t length) {
    while (length > 0) {
        ssize_t received = recv(fd, data, length, 0);
        if (received <= 0) return -1;
        data += received;
        length -= (size_t)received;
    }
    return 0;
}

static size_t put_u16(unsigned char *packet, size_t offset, uint16_t value) {
    value = htons(value);
    memcpy(packet + offset, &value, sizeof(value));
    return offset + sizeof(value);
}

static uint16_t get_u16(const unsigned char *packet, size_t offset) {
    uint16_t value;
    memcpy(&value, packet + offset, sizeof(value));
    return ntohs(value);
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "udp") != 0 && strcmp(argv[1], "tcp") != 0)) {
        fprintf(stderr, "usage: dns_probe udp|tcp name\n");
        return 2;
    }

    unsigned char query[512] = {0};
    put_u16(query, 0, 0x4a31);
    put_u16(query, 2, 0x0100); /* recursion desired */
    put_u16(query, 4, 1);
    size_t length = 12;
    char name[256];
    if (strlen(argv[2]) >= sizeof(name)) return 2;
    strcpy(name, argv[2]);
    char *save = NULL;
    for (char *label = strtok_r(name, ".", &save); label != NULL; label = strtok_r(NULL, ".", &save)) {
        size_t label_length = strlen(label);
        if (label_length == 0 || label_length > 63 || length + label_length + 5 >= sizeof(query)) return 2;
        query[length++] = (unsigned char)label_length;
        memcpy(query + length, label, label_length);
        length += label_length;
    }
    query[length++] = 0;
    length = put_u16(query, length, 1); /* A */
    length = put_u16(query, length, 1); /* IN */

    int tcp = strcmp(argv[1], "tcp") == 0;
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in server = {.sin_family = AF_INET, .sin_port = htons(53)};
    inet_pton(AF_INET, "10.0.2.3", &server.sin_addr);
    unsigned char response[4096];
    size_t response_length;

    if (tcp) {
        if (connect(fd, (struct sockaddr *)&server, sizeof(server)) != 0) { perror("connect"); return 1; }
        unsigned char framed[514];
        uint16_t frame_length = htons((uint16_t)length);
        memcpy(framed, &frame_length, 2);
        memcpy(framed + 2, query, length);
        if (send_all(fd, framed, length + 2) != 0) { perror("send"); return 1; }
        if (recv_all(fd, (unsigned char *)&frame_length, 2) != 0) { perror("recv length"); return 1; }
        response_length = ntohs(frame_length);
        if (response_length > sizeof(response) || recv_all(fd, response, response_length) != 0) {
            perror("recv response"); return 1;
        }
    } else {
        if (sendto(fd, query, length, 0, (struct sockaddr *)&server, sizeof(server)) < 0) { perror("sendto"); return 1; }
        ssize_t received = recv(fd, response, sizeof(response), 0);
        if (received < 12) { perror("recv"); return 1; }
        response_length = (size_t)received;
    }
    close(fd);
    if (response_length < 12 || get_u16(response, 0) != 0x4a31) {
        fprintf(stderr, "invalid DNS response\n"); return 1;
    }
    unsigned flags = get_u16(response, 2);
    printf("rcode=%u answers=%u\n", flags & 15, get_u16(response, 6));
    size_t i = 12;
    for (; i < response_length;) {
        unsigned char size = response[i++];
        if (size == 0) break;
        if ((size & 0xc0) == 0xc0) { i++; break; }
        if (size > 63 || i + size > response_length) break;
        i += size;
    }
    i += 4; /* skip question type/class */
    unsigned answer_count = get_u16(response, 6);
    for (unsigned index = 0; index < answer_count && i + 2 <= response_length; index++) {
        if ((response[i] & 0xc0) == 0xc0) i += 2;
        else {
            while (i < response_length && response[i] != 0) i += (size_t)response[i] + 1;
            i++;
        }
        if (i + 10 > response_length) break;
        uint16_t type = get_u16(response, i);
        uint16_t data_length = get_u16(response, i + 8);
        i += 10;
        if (i + data_length > response_length) break;
        if (type == 1 && data_length == 4) {
            char address[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, response + i, address, sizeof(address)) != NULL) printf("a=%s\n", address);
        }
        i += data_length;
    }
    return 0;
}
