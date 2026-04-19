#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
typedef int socket_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#endif

#include <vector>
#include <map>
#include <set>
#include <deque>
#include <string>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ParsedTextMessage {
    uint16_t aa;
    int32_t bbb;
    unsigned char hh;
    unsigned char mm;
    unsigned char ss;
    std::string text;
};

struct WireMessage {
    uint32_t index;
    ParsedTextMessage msg;
};

struct PeerKey {
    uint32_t ip;
    uint16_t port;

    bool operator<(const PeerKey &other) const {
        if (ip < other.ip) {
            return true;
        }
        if (ip > other.ip) {
            return false;
        }
        return port < other.port;
    }
};

struct ClientInfo {
    time_t last_activity;
    std::set<uint32_t> received_indices;
    std::deque<uint32_t> recent_indices;
};

static bool net_init() {
#ifdef _WIN32
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
#else
    return true;
#endif
}

static void net_cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

static int net_last_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static void net_close(socket_t s) {
    if (s == INVALID_SOCKET) {
        return;
    }
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

static bool set_non_blocking(socket_t s) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static int socket_send_flags() {
#ifdef _WIN32
    return 0;
#else
    return MSG_NOSIGNAL;
#endif
}

static bool socket_would_block(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EWOULDBLOCK || err == EAGAIN;
#endif
}

static bool parse_port_number_text(const std::string &text, unsigned short &port) {
    unsigned long acc = 0;
    std::string::size_type i;
    if (text.empty()) {
        return false;
    }
    for (i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (c < '0' || c > '9') {
            return false;
        }
        acc = acc * 10UL + (unsigned long)(c - '0');
        if (acc > 65535UL) {
            return false;
        }
    }
    if (acc == 0UL) {
        return false;
    }
    port = (unsigned short)acc;
    return true;
}

static void append_u32_be(std::string &out, uint32_t value) {
    out.push_back((char)((value >> 24) & 0xFFu));
    out.push_back((char)((value >> 16) & 0xFFu));
    out.push_back((char)((value >> 8) & 0xFFu));
    out.push_back((char)(value & 0xFFu));
}

static uint16_t read_u16_be(const char *data) {
    const unsigned char *u = (const unsigned char *)data;
    return (uint16_t)(((uint16_t)u[0] << 8) | (uint16_t)u[1]);
}

static uint32_t read_u32_be(const char *data) {
    const unsigned char *u = (const unsigned char *)data;
    return ((uint32_t)u[0] << 24) |
           ((uint32_t)u[1] << 16) |
           ((uint32_t)u[2] << 8) |
           (uint32_t)u[3];
}

static bool decode_wire_message(const char *data, size_t size, WireMessage &out, size_t *used_size) {
    uint32_t text_len;
    size_t total_size;
    if (size < 17u) {
        return false;
    }
    out.index = read_u32_be(data);
    out.msg.aa = read_u16_be(data + 4);
    out.msg.bbb = (int32_t)read_u32_be(data + 6);
    out.msg.hh = (unsigned char)data[10];
    out.msg.mm = (unsigned char)data[11];
    out.msg.ss = (unsigned char)data[12];
    text_len = read_u32_be(data + 13);
    total_size = 17u + (size_t)text_len;
    if (size < total_size) {
        return false;
    }
    out.msg.text.assign(data + 17, data + total_size);
    if (used_size) {
        *used_size = total_size;
    }
    return true;
}

static bool decode_wire_message_exact(const char *data, size_t size, WireMessage &out) {
    size_t used_size = 0;
    if (!decode_wire_message(data, size, out, &used_size)) {
        return false;
    }
    return used_size == size;
}

static std::string message_to_text_line(const ParsedTextMessage &msg) {
    char buffer[64];
    std::string result;
    sprintf(buffer, "%u %d %02u:%02u:%02u ",
            (unsigned int)msg.aa,
            (int)msg.bbb,
            (unsigned int)msg.hh,
            (unsigned int)msg.mm,
            (unsigned int)msg.ss);
    result = buffer;
    result += msg.text;
    return result;
}

static bool append_message_to_log(FILE *log_file, const struct sockaddr_in &from, const WireMessage &msg) {
    std::string text = message_to_text_line(msg.msg);
    const char *ip_text = inet_ntoa(from.sin_addr);
    if (fprintf(log_file, "%s:%u %s\n",
                ip_text ? ip_text : "0.0.0.0",
                (unsigned int)ntohs(from.sin_port),
                text.c_str()) < 0) {
        return false;
    }
    fflush(log_file);
    return true;
}

static void update_recent_indices(ClientInfo &info, uint32_t idx) {
    if (info.received_indices.insert(idx).second) {
        info.recent_indices.push_back(idx);
        if (info.recent_indices.size() > 20u) {
            info.recent_indices.pop_front();
        }
    }
}

static void send_confirmation(socket_t sock, const struct sockaddr_in &to, const ClientInfo &info) {
    std::string response;
    std::deque<uint32_t>::const_reverse_iterator it;
    for (it = info.recent_indices.rbegin(); it != info.recent_indices.rend(); ++it) {
        append_u32_be(response, *it);
    }
    if (response.empty()) {
        return;
    }
    sendto(sock,
           response.data(),
           (int)response.size(),
           socket_send_flags(),
           (const struct sockaddr *)&to,
           sizeof(to));
}

static bool process_one_datagram(socket_t sock,
                                 FILE *log_file,
                                 std::map<PeerKey, ClientInfo> &clients,
                                 bool &stop_requested) {
    char buffer[65535];
    struct sockaddr_in from;
#ifdef _WIN32
    int from_len = sizeof(from);
#else
    socklen_t from_len = sizeof(from);
#endif
    int rc = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
    if (rc == SOCKET_ERROR) {
        int err = net_last_error();
        if (!socket_would_block(err)) {
            fprintf(stdout, "recvfrom() failed: %d\n", err);
        }
        return false;
    }

    {
        PeerKey key;
        WireMessage msg;

        key.ip = (uint32_t)from.sin_addr.s_addr;
        key.port = (uint16_t)from.sin_port;

        if (!decode_wire_message_exact(buffer, (size_t)rc, msg)) {
            fprintf(stdout, "Invalid UDP datagram from %s:%u\n",
                    inet_ntoa(from.sin_addr), (unsigned int)ntohs(from.sin_port));
            return true;
        }

        ClientInfo &info = clients[key];
        info.last_activity = time(0);

        if (info.received_indices.find(msg.index) == info.received_indices.end()) {
            update_recent_indices(info, msg.index);
            if (!append_message_to_log(log_file, from, msg)) {
                fprintf(stdout, "Failed to write msg.txt\n");
            }
        }

        send_confirmation(sock, from, info);

        if (msg.msg.text == "stop") {
            stop_requested = true;
        }
    }

    return true;
}

static void cleanup_inactive_clients(std::map<PeerKey, ClientInfo> &clients) {
    std::map<PeerKey, ClientInfo>::iterator it = clients.begin();
    time_t now = time(0);
    while (it != clients.end()) {
        if ((now - it->second.last_activity) > 30) {
            std::map<PeerKey, ClientInfo>::iterator current = it;
            ++it;
            clients.erase(current);
        } else {
            ++it;
        }
    }
}

int main(int argc, char **argv) {
    unsigned short port_from;
    unsigned short port_to;
    std::vector<socket_t> sockets;
    std::map<PeerKey, ClientInfo> clients;
    FILE *log_file;
    bool stop_requested = false;

    if (argc != 3) {
        fprintf(stdout, "Usage: udpserver PORT_FROM PORT_TO\n");
        return 1;
    }

    if (!parse_port_number_text(argv[1], port_from) ||
        !parse_port_number_text(argv[2], port_to) ||
        port_from > port_to) {
        fprintf(stdout, "Invalid UDP port range\n");
        return 1;
    }

    if (!net_init()) {
        fprintf(stdout, "Socket library init failed\n");
        return 1;
    }

    log_file = fopen("msg.txt", "a");
    if (!log_file) {
        fprintf(stdout, "Cannot open msg.txt for writing\n");
        net_cleanup();
        return 1;
    }

    for (unsigned int port = port_from; port <= port_to; ++port) {
        socket_t s;
        struct sockaddr_in addr;
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) {
            fprintf(stdout, "socket() failed for port %u: %d\n", port, net_last_error());
            stop_requested = true;
            break;
        }
        if (!set_non_blocking(s)) {
            fprintf(stdout, "Failed to set nonblocking mode for port %u\n", port);
            net_close(s);
            stop_requested = true;
            break;
        }
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons((unsigned short)port);
        if (bind(s, (const struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            fprintf(stdout, "bind() failed for port %u: %d\n", port, net_last_error());
            net_close(s);
            stop_requested = true;
            break;
        }
        sockets.push_back(s);
    }

    if (!stop_requested) {
        fprintf(stdout, "Listening UDP ports: %u..%u\n",
                (unsigned int)port_from,
                (unsigned int)port_to);
    }

    while (!stop_requested) {
        fd_set rfds;
        struct timeval tv;
        socket_t max_fd = 0;
        std::vector<socket_t>::size_type i;

        if (sockets.empty()) {
            break;
        }

        FD_ZERO(&rfds);
        for (i = 0; i < sockets.size(); ++i) {
            FD_SET(sockets[i], &rfds);
            if (sockets[i] > max_fd) {
                max_fd = sockets[i];
            }
        }
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

#ifdef _WIN32
        {
            int rc = select(0, &rfds, 0, 0, &tv);
            if (rc == SOCKET_ERROR) {
                fprintf(stdout, "select() failed: %d\n", net_last_error());
                break;
            }
        }
#else
        {
            int rc = select((int)(max_fd + 1), &rfds, 0, 0, &tv);
            if (rc == SOCKET_ERROR) {
                fprintf(stdout, "select() failed: %d\n", net_last_error());
                break;
            }
        }
#endif

        for (i = 0; i < sockets.size() && !stop_requested; ++i) {
            if (FD_ISSET(sockets[i], &rfds)) {
                process_one_datagram(sockets[i], log_file, clients, stop_requested);
            }
        }

        cleanup_inactive_clients(clients);
    }

    for (std::vector<socket_t>::size_type i = 0; i < sockets.size(); ++i) {
        net_close(sockets[i]);
    }

    fclose(log_file);
    net_cleanup();
    return 0;
}