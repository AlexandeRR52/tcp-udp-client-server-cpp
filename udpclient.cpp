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
#include <errno.h>
typedef int socket_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#endif

#include <fstream>
#include <vector>
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

struct DatagramItem {
    uint32_t index;
    std::string data;
    bool confirmed;
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

static int socket_send_flags() {
#ifdef _WIN32
    return 0;
#else
    return MSG_NOSIGNAL;
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

static uint32_t read_u32_be(const char *data) {
    const unsigned char *u = (const unsigned char *)data;
    return ((uint32_t)u[0] << 24) |
           ((uint32_t)u[1] << 16) |
           ((uint32_t)u[2] << 8) |
           (uint32_t)u[3];
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

static bool wait_readable(socket_t s, long timeout_ms) {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
    return select(0, &rfds, 0, 0, &tv) > 0;
#else
    return select((int)(s + 1), &rfds, 0, 0, &tv) > 0;
#endif
}

static bool load_messages(const char *filename, std::vector<DatagramItem> &items) {
    std::ifstream input(filename, std::ios::in | std::ios::binary);
    std::string line;
    uint32_t index = 0;
    if (!input.is_open()) {
        return false;
    }
    while (std::getline(input, line)) {
        ParsedTextMessage msg;
        DatagramItem item;
        trim_trailing_cr(line);
        if (line.empty()) {
            continue;
        }
        if (!parse_text_message_line(line, msg)) {
            fprintf(stdout, "Skipping invalid input line: %s\n", line.c_str());
            continue;
        }
        item.index = index;
        item.confirmed = false;
        if (!encode_wire_message(index, msg, item.data)) {
            fprintf(stdout, "Skipping too large message at index %u\n", (unsigned int)index);
            continue;
        }
        items.push_back(item);
        ++index;
    }
    return true;
}

static void process_confirmation_datagram(const char *data,
                                          int size,
                                          std::vector<DatagramItem> &items,
                                          unsigned int &confirmed_count) {
    int pos = 0;
    while (pos + 4 <= size) {
        uint32_t idx = read_u32_be(data + pos);
        if (idx < items.size() && !items[(size_t)idx].confirmed) {
            items[(size_t)idx].confirmed = true;
            ++confirmed_count;
        }
        pos += 4;
    }
}

int main(int argc, char **argv) {
    struct sockaddr_in server_addr;
    socket_t sock = INVALID_SOCKET;
    std::vector<DatagramItem> items;
    unsigned int confirmed_count = 0;
    unsigned int target_count;

    if (argc != 3) {
        fprintf(stdout, "Usage: udpclient IP:PORT INPUT_FILE\n");
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

    if (!load_messages(argv[2], items)) {
        fprintf(stdout, "Cannot open input file: %s\n", argv[2]);
        net_cleanup();
        return 1;
    }

    if (items.empty()) {
        fprintf(stdout, "No messages to send\n");
        net_cleanup();
        return 0;
    }

    target_count = (unsigned int)items.size();

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        fprintf(stdout, "socket() failed: %d\n", net_last_error());
        net_cleanup();
        return 1;
    }

    if (connect(sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stdout, "connect() failed for UDP socket: %d\n", net_last_error());
        net_close(sock);
        net_cleanup();
        return 1;
    }

    while (confirmed_count < target_count) {
        std::vector<DatagramItem>::size_type i;

        for (i = 0; i < items.size(); ++i) {
            int rc;
            if (items[i].confirmed) {
                continue;
            }
            rc = send(sock,
                      items[i].data.data(),
                      (int)items[i].data.size(),
                      socket_send_flags());
            if (rc == SOCKET_ERROR) {
                fprintf(stdout, "sendto() failed for message %u: %d\n",
                        (unsigned int)items[i].index,
                        net_last_error());
            }
        }

        while (confirmed_count < target_count) {
            char buffer[4096];
            int rc;

            if (!wait_readable(sock, 100)) {
                break;
            }

            rc = recv(sock, buffer, sizeof(buffer), 0);
            if (rc == SOCKET_ERROR) {
                fprintf(stdout, "recvfrom() failed: %d\n", net_last_error());
                break;
            }
            process_confirmation_datagram(buffer, rc, items, confirmed_count);
        }
    }

    fprintf(stdout, "Confirmed %u message(s) from %u required\n", confirmed_count, target_count);

    net_close(sock);
    net_cleanup();
    return 0;
}
