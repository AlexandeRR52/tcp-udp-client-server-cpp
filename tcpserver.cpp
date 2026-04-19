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
typedef int socklen_compat_t;
typedef WSAPOLLFD PollFd;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
typedef int socket_t;
typedef socklen_t socklen_compat_t;
typedef struct pollfd PollFd;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#endif

#include <vector>
#include <string>
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

struct ClientState {
    socket_t sock;
    std::string peer_ip;
    unsigned short peer_port;
    std::vector<char> inbuf;
    std::string outbuf;
    size_t out_offset;
    bool command_received;
    bool closed;
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

static int poll_wait(PollFd *fds, unsigned int count, int timeout_ms) {
#ifdef _WIN32
    return WSAPoll(fds, count, timeout_ms);
#else
    return poll(fds, count, timeout_ms);
#endif
}

static void close_client(ClientState *client) {
    if (!client->closed) {
        net_close(client->sock);
        client->sock = INVALID_SOCKET;
        client->closed = true;
    }
}

static void cleanup_closed_clients(std::vector<ClientState *> &clients, ClientState **stop_client_ptr) {
    std::vector<ClientState *>::size_type i = 0;
    while (i < clients.size()) {
        if (clients[i]->closed) {
            if (*stop_client_ptr == clients[i]) {
                *stop_client_ptr = 0;
            }
            delete clients[i];
            clients.erase(clients.begin() + (long)i);
        } else {
            ++i;
        }
    }
}

static void queue_ok(ClientState *client) {
    client->outbuf.append("ok", 2);
}

static bool write_log_line(FILE *log_file, ClientState *client, const WireMessage &msg) {
    std::string text = message_to_text_line(msg.msg);
    if (fprintf(log_file, "%s:%u %s\n", client->peer_ip.c_str(), (unsigned int)client->peer_port, text.c_str()) < 0) {
        return false;
    }
    fflush(log_file);
    return true;
}

static void flush_outgoing(ClientState *client) {
    while (client->out_offset < client->outbuf.size()) {
        int rc = send(client->sock,
                      client->outbuf.data() + client->out_offset,
                      (int)(client->outbuf.size() - client->out_offset),
                      socket_send_flags());
        if (rc > 0) {
            client->out_offset += (size_t)rc;
        } else if (rc == 0) {
            close_client(client);
            return;
        } else {
            int err = net_last_error();
            if (socket_would_block(err)) {
                return;
            }
            fprintf(stdout, "send() failed for %s:%u: %d\n",
                    client->peer_ip.c_str(), (unsigned int)client->peer_port, err);
            close_client(client);
            return;
        }
    }

    if (client->out_offset >= client->outbuf.size()) {
        client->outbuf.clear();
        client->out_offset = 0;
    }
}

static void process_messages_from_buffer(ClientState *client,
                                         FILE *log_file,
                                         bool &stop_requested,
                                         ClientState *&stop_client) {
    for (;;) {
        WireMessage msg;
        size_t used = 0;
        if (client->inbuf.empty()) {
            return;
        }
        if (!client->command_received) {
            if (client->inbuf.size() < 3u) {
                return;
            }
            if (client->inbuf[0] != 'p' || client->inbuf[1] != 'u' || client->inbuf[2] != 't') {
                fprintf(stdout, "Invalid client command from %s:%u\n",
                        client->peer_ip.c_str(), (unsigned int)client->peer_port);
                close_client(client);
                return;
            }
            client->command_received = true;
            client->inbuf.erase(client->inbuf.begin(), client->inbuf.begin() + 3);
            if (client->inbuf.empty()) {
                return;
            }
        }
        if (!decode_wire_message(&client->inbuf[0], client->inbuf.size(), msg, &used)) {
            return;
        }
        if (!write_log_line(log_file, client, msg)) {
            fprintf(stdout, "Failed to write msg.txt\n");
            close_client(client);
            return;
        }
        queue_ok(client);
        client->inbuf.erase(client->inbuf.begin(), client->inbuf.begin() + (long)used);
        if (msg.msg.text == "stop" && !stop_requested) {
            stop_requested = true;
            stop_client = client;
        }
    }
}

static void read_client_data(ClientState *client,
                             FILE *log_file,
                             bool &stop_requested,
                             ClientState *&stop_client) {
    char buffer[4096];
    for (;;) {
        int rc = recv(client->sock, buffer, sizeof(buffer), 0);
        if (rc > 0) {
            client->inbuf.insert(client->inbuf.end(), buffer, buffer + rc);
            process_messages_from_buffer(client, log_file, stop_requested, stop_client);
            if (client->closed) {
                return;
            }
        } else if (rc == 0) {
            close_client(client);
            return;
        } else {
            int err = net_last_error();
            if (socket_would_block(err)) {
                break;
            }
            fprintf(stdout, "recv() failed for %s:%u: %d\n",
                    client->peer_ip.c_str(), (unsigned int)client->peer_port, err);
            close_client(client);
            return;
        }
    }

    if (!client->outbuf.empty() && !client->closed) {
        flush_outgoing(client);
    }
}

static bool add_new_client(socket_t accepted_sock,
                           const struct sockaddr_in &addr,
                           std::vector<ClientState *> &clients) {
    ClientState *client = new ClientState();
    const char *ip_text;
    if (!client) {
        net_close(accepted_sock);
        return false;
    }
    client->sock = accepted_sock;
    client->peer_port = ntohs(addr.sin_port);
    ip_text = inet_ntoa(addr.sin_addr);
    client->peer_ip = ip_text ? ip_text : "0.0.0.0";
    client->out_offset = 0;
    client->command_received = false;
    client->closed = false;
    if (!set_non_blocking(client->sock)) {
        fprintf(stdout, "Failed to set nonblocking mode for %s:%u\n",
                client->peer_ip.c_str(), (unsigned int)client->peer_port);
        close_client(client);
        delete client;
        return false;
    }
    clients.push_back(client);
    fprintf(stdout, "Client connected: %s:%u\n", client->peer_ip.c_str(), (unsigned int)client->peer_port);
    return true;
}

static void accept_new_connections(socket_t listener, std::vector<ClientState *> &clients) {
    for (;;) {
        struct sockaddr_in addr;
        socklen_compat_t addr_len = sizeof(addr);
        socket_t accepted_sock = accept(listener, (struct sockaddr *)&addr, &addr_len);
        if (accepted_sock == INVALID_SOCKET) {
            int err = net_last_error();
            if (!socket_would_block(err)) {
                fprintf(stdout, "accept() failed: %d\n", err);
            }
            return;
        }
        add_new_client(accepted_sock, addr, clients);
    }
}

int main(int argc, char **argv) {
    unsigned short port;
    socket_t listener = INVALID_SOCKET;
    struct sockaddr_in addr;
    std::vector<ClientState *> clients;
    bool stop_requested = false;
    ClientState *stop_client = 0;
    FILE *log_file;

    if (argc != 2) {
        fprintf(stdout, "Usage: tcpserver PORT\n");
        return 1;
    }

    if (!parse_port_number_text(argv[1], port)) {
        fprintf(stdout, "Invalid TCP port: %s\n", argv[1]);
        return 1;
    }

    if (!net_init()) {
        fprintf(stdout, "WSAStartup/init failed\n");
        return 1;
    }

    log_file = fopen("msg.txt", "a");
    if (!log_file) {
        fprintf(stdout, "Cannot open msg.txt for writing\n");
        net_cleanup();
        return 1;
    }

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET) {
        fprintf(stdout, "socket() failed: %d\n", net_last_error());
        fclose(log_file);
        net_cleanup();
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listener, (const struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stdout, "bind()/listen() failed: %d\n", net_last_error());
        net_close(listener);
        fclose(log_file);
        net_cleanup();
        return 1;
    }

    if (!set_non_blocking(listener)) {
        fprintf(stdout, "Cannot set listener to nonblocking mode\n");
        net_close(listener);
        fclose(log_file);
        net_cleanup();
        return 1;
    }

    fprintf(stdout, "Listening on TCP port %u\n", (unsigned int)port);

    while (1) {
        std::vector<PollFd> poll_fds;
        std::vector<int> client_index_map;
        unsigned int i;
        int ready_count;

        poll_fds.reserve(clients.size() + 1u);
        client_index_map.reserve(clients.size() + 1u);

        {
            PollFd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = listener;
            pfd.events = stop_requested ? 0 : POLLIN;
            poll_fds.push_back(pfd);
            client_index_map.push_back(-1);
        }

        for (i = 0; i < clients.size(); ++i) {
            PollFd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = clients[i]->sock;
            pfd.events = POLLIN;
            if (!clients[i]->outbuf.empty()) {
                pfd.events = (short)(pfd.events | POLLOUT);
            }
            poll_fds.push_back(pfd);
            client_index_map.push_back((int)i);
        }

        ready_count = poll_wait(&poll_fds[0], (unsigned int)poll_fds.size(), 1000);
        if (ready_count < 0) {
            fprintf(stdout, "poll()/WSAPoll() failed: %d\n", net_last_error());
            break;
        }

        if (ready_count > 0) {
            if (!stop_requested && (poll_fds[0].revents & POLLIN)) {
                accept_new_connections(listener, clients);
            }

            for (i = 1; i < poll_fds.size(); ++i) {
                short revents = poll_fds[i].revents;
                int client_idx = client_index_map[i];
                ClientState *client;
                if (client_idx < 0 || client_idx >= (int)clients.size()) {
                    continue;
                }
                client = clients[(size_t)client_idx];

                if (revents == 0) {
                    continue;
                }
                if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    close_client(client);
                    continue;
                }
                if ((revents & POLLIN) && (!stop_requested || client == stop_client)) {
                    read_client_data(client, log_file, stop_requested, stop_client);
                    if (client->closed) {
                        continue;
                    }
                }
                if ((revents & POLLOUT) && !client->closed && !client->outbuf.empty()) {
                    flush_outgoing(client);
                }
            }
        }

        cleanup_closed_clients(clients, &stop_client);

        if (stop_requested) {
            if (stop_client == 0 || stop_client->closed) {
                break;
            }
            if (stop_client->outbuf.empty()) {
                break;
            }
        }
    }

    for (std::vector<ClientState *>::size_type i = 0; i < clients.size(); ++i) {
        close_client(clients[i]);
        delete clients[i];
    }

    net_close(listener);
    fclose(log_file);
    net_cleanup();
    return 0;
}
