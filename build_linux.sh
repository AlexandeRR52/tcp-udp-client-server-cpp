#!/usr/bin/env bash
set -e

g++ -std=c++11 -Wall -Wextra -O2 tcpclient.cpp -o tcpclient
g++ -std=c++11 -Wall -Wextra -O2 tcpserver.cpp -o tcpserver
g++ -std=c++11 -Wall -Wextra -O2 udpclient.cpp -o udpclient
g++ -std=c++11 -Wall -Wextra -O2 udpserver.cpp -o udpserver

echo "Build completed."
