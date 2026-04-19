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
#endif

#include <fstream>
#include <string>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct ParsedTextMessage {
    uint16_t aa;
    int32_t bbb;
    unsigned char hh;
    unsigned char mm;
    unsigned char ss;
    std::string text;
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

static void sleep_ms(unsigned int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000u);
#endif
}

static bool set_blocking_mode(socket_t s, bool blocking) {
#ifdef _WIN32
    u_long mode = blocking ? 0UL : 1UL;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    return fcntl(s, F_SETFL, flags) == 0;
#endif
}

static bool socket_connect_in_progress(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINVAL;
#else
    return err == EINPROGRESS || err == EWOULDBLOCK || err == EAGAIN;
#endif
}

static bool wait_socket_writable(socket_t s, long timeout_ms) {
    fd_set wfds;
    fd_set efds;
    struct timeval tv;
    int rc;

    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(s, &wfds);
    FD_SET(s, &efds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

#ifdef _WIN32
    rc = select(0, 0, &wfds, &efds, &tv);
#else
    rc = select((int)(s + 1), 0, &wfds, &efds, &tv);
#endif
    return rc > 0 && (FD_ISSET(s, &wfds) || FD_ISSET(s, &efds));
}

static bool connect_with_timeout(socket_t s, const struct sockaddr_in &server_addr, long timeout_ms) {
    int rc;
    int err;
    int so_error = 0;
#ifdef _WIN32
    int so_error_len = sizeof(so_error);
#else
    socklen_t so_error_len = sizeof(so_error);
#endif

    if (!set_blocking_mode(s, false)) {
        return false;
    }

    rc = connect(s, (const struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc == 0) {
        return set_blocking_mode(s, true);
    }

    err = net_last_error();
    if (!socket_connect_in_progress(err)) {
        set_blocking_mode(s, true);
        return false;
    }

    if (!wait_socket_writable(s, timeout_ms)) {
        set_blocking_mode(s, true);
        return false;
    }

    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_error_len) != 0) {
        set_blocking_mode(s, true);
        return false;
    }

    if (!set_blocking_mode(s, true)) {
        return false;
    }

    return so_error == 0;
}

static int socket_send_flags() {
#ifdef _WIN32
    return 0;
#else
    return MSG_NOSIGNAL;
#endif
}

static bool recv_exact(socket_t s, char *buf, size_t size) {
    size_t done = 0;
    while (done < size) {
        int rc = recv(s, buf + done, (int)(size - done), 0);
        if (rc <= 0) {
            return false;
        }
        done += (size_t)rc;
    }
    return true;
}

static bool send_all(socket_t s, const char *buf, size_t size) {
    size_t done = 0;
    while (done < size) {
        int rc = send(s, buf + done, (int)(size - done), socket_send_flags());
        if (rc <= 0) {
            return false;
        }
        done += (size_t)rc;
    }
    return true;
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

static bool parse_ipv4_endpoint(const std::string &spec, struct sockaddr_in &addr) {
    std::string::size_type pos = spec.rfind(':');
    std::string ip_text;
    std::string port_text;
    unsigned short port;
    unsigned long ip;

    if (pos == std::string::npos) {
        return false;
    }

    ip_text = spec.substr(0, pos);
    port_text = spec.substr(pos + 1);
    if (ip_text.empty() || !parse_port_number_text(port_text, port)) {
        return false;
    }

    ip = inet_addr(ip_text.c_str());
    if (ip == INADDR_NONE && ip_text != "255.255.255.255") {
        return false;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ip;
    return true;
}

static void trim_trailing_cr(std::string &line) {
    if (!line.empty() && line[line.size() - 1] == '\r') {
        line.erase(line.size() - 1);
    }
}

static bool parse_u16_field(const std::string &text, uint16_t &value) {
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
    value = (uint16_t)acc;
    return true;
}

static bool parse_i32_field(const std::string &text, int32_t &value) {
    bool negative = false;
    long long acc = 0;
    std::string::size_type i = 0;
    if (text.empty()) {
        return false;
    }
    if (text[0] == '-') {
        negative = true;
        i = 1;
    }
    if (i >= text.size()) {
        return false;
    }
    for (; i < text.size(); ++i) {
        char c = text[i];
        if (c < '0' || c > '9') {
            return false;
        }
        acc = acc * 10LL + (long long)(c - '0');
        if ((!negative && acc > 2147483647LL) || (negative && acc > 2147483648LL)) {
            return false;
        }
    }
    if (negative) {
        if (acc == 2147483648LL) {
            value = (int32_t)0x80000000u;
        } else {
            value = (int32_t)(-acc);
        }
    } else {
        value = (int32_t)acc;
    }
    return true;
}

static bool parse_time_field(const std::string &text, unsigned char &hh, unsigned char &mm, unsigned char &ss) {
    int h, m, s;
    if (text.size() != 8) {
        return false;
    }
    if (text[2] != ':' || text[5] != ':') {
        return false;
    }
    if (text[0] < '0' || text[0] > '9' || text[1] < '0' || text[1] > '9' ||
        text[3] < '0' || text[3] > '9' || text[4] < '0' || text[4] > '9' ||
        text[6] < '0' || text[6] > '9' || text[7] < '0' || text[7] > '9') {
        return false;
    }

    h = (text[0] - '0') * 10 + (text[1] - '0');
    m = (text[3] - '0') * 10 + (text[4] - '0');
    s = (text[6] - '0') * 10 + (text[7] - '0');
    if (h > 23 || m > 59 || s > 59) {
        return false;
    }

    hh = (unsigned char)h;
    mm = (unsigned char)m;
    ss = (unsigned char)s;
    return true;
}

static bool parse_text_message_line(const std::string &line, ParsedTextMessage &msg) {
    std::string::size_type p1 = line.find(' ');
    std::string::size_type p2;
    std::string::size_type p3;

    if (p1 == std::string::npos) {
        return false;
    }

    p2 = line.find(' ', p1 + 1);
    if (p2 == std::string::npos) {
        return false;
    }

    p3 = line.find(' ', p2 + 1);
    if (p3 == std::string::npos) {
        return false;
    }

    if (!parse_u16_field(line.substr(0, p1), msg.aa) ||
        !parse_i32_field(line.substr(p1 + 1, p2 - p1 - 1), msg.bbb) ||
        !parse_time_field(line.substr(p2 + 1, p3 - p2 - 1), msg.hh, msg.mm, msg.ss)) {
        return false;
    }

    msg.text = line.substr(p3 + 1);
    return true;
}

static void append_u16_be(std::string &out, uint16_t value) {
    out.push_back((char)((value >> 8) & 0xFFu));
    out.push_back((char)(value & 0xFFu));
}

static void append_u32_be(std::string &out, uint32_t value) {
    out.push_back((char)((value >> 24) & 0xFFu));
    out.push_back((char)((value >> 16) & 0xFFu));
    out.push_back((char)((value >> 8) & 0xFFu));
    out.push_back((char)(value & 0xFFu));
}

static bool encode_wire_message(uint32_t index, const ParsedTextMessage &msg, std::string &out) {
    if (msg.text.size() > 0xFFFFFFFFu) {
        return false;
    }
    out.clear();
    append_u32_be(out, index);
    append_u16_be(out, msg.aa);
    append_u32_be(out, (uint32_t)msg.bbb);
    out.push_back((char)msg.hh);
    out.push_back((char)msg.mm);
    out.push_back((char)msg.ss);
    append_u32_be(out, (uint32_t)msg.text.size());
    out += msg.text;
    return true;
}

static socket_t connect_with_retries(const struct sockaddr_in &server_addr) {
    int attempt;
    for (attempt = 1; attempt <= 10; ++attempt) {
        socket_t s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) {
            fprintf(stdout, "socket() failed: %d\n", net_last_error());
            return INVALID_SOCKET;
        }

        if (connect_with_timeout(s, server_addr, 100)) {
            return s;
        }

        fprintf(stdout, "connect attempt %d/10 failed: %d\n", attempt, net_last_error());
        net_close(s);
        if (attempt < 10) {
            sleep_ms(100);
        }
    }
    return INVALID_SOCKET;
}

int main(int argc, char **argv) {
    struct sockaddr_in server_addr;
    std::ifstream input;
    socket_t sock = INVALID_SOCKET;
    std::string line;
    uint32_t index = 0;

    if (argc != 3) {
        fprintf(stdout, "Usage: tcpclient IP:PORT INPUT_FILE\n");
        return 1;
    }

    if (!net_init()) {
        fprintf(stdout, "WSAStartup/init failed\n");
        return 1;
    }

    if (!parse_ipv4_endpoint(argv[1], server_addr)) {
        fprintf(stdout, "Invalid server endpoint: %s\n", argv[1]);
        net_cleanup();
        return 1;
    }

    input.open(argv[2], std::ios::in | std::ios::binary);
    if (!input.is_open()) {
        fprintf(stdout, "Cannot open input file: %s\n", argv[2]);
        net_cleanup();
        return 1;
    }

    sock = connect_with_retries(server_addr);
    if (sock == INVALID_SOCKET) {
        fprintf(stdout, "Failed to connect after 10 attempts\n");
        input.close();
        net_cleanup();
        return 1;
    }

    if (!send_all(sock, "put", 3)) {
        fprintf(stdout, "Failed to send initial command: %d\n", net_last_error());
        net_close(sock);
        input.close();
        net_cleanup();
        return 1;
    }

    while (std::getline(input, line)) {
        ParsedTextMessage msg;
        std::string packet;
        char ack[2];

        trim_trailing_cr(line);
        if (line.empty()) {
            continue;
        }
        if (!parse_text_message_line(line, msg)) {
            fprintf(stdout, "Skipping invalid input line: %s\n", line.c_str());
            continue;
        }
        if (!encode_wire_message(index, msg, packet)) {
            fprintf(stdout, "Skipping too large message at index %u\n", (unsigned int)index);
            continue;
        }
        if (!send_all(sock, packet.data(), packet.size())) {
            fprintf(stdout, "Send failed at message %u: %d\n", (unsigned int)index, net_last_error());
            net_close(sock);
            input.close();
            net_cleanup();
            return 1;
        }
        if (!recv_exact(sock, ack, sizeof(ack))) {
            fprintf(stdout, "Connection closed while waiting for ack at message %u\n", (unsigned int)index);
            net_close(sock);
            input.close();
            net_cleanup();
            return 1;
        }
        if (ack[0] != 'o' || ack[1] != 'k') {
            fprintf(stdout, "Invalid ack at message %u\n", (unsigned int)index);
            net_close(sock);
            input.close();
            net_cleanup();
            return 1;
        }
        ++index;
    }

    fprintf(stdout, "Sent %u message(s)\n", (unsigned int)index);

    net_close(sock);
    input.close();
    net_cleanup();
    return 0;
}
