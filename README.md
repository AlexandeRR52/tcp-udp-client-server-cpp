# TCP/UDP Client-Server Applications (C++)

Educational project demonstrating client-server communication using TCP and UDP protocols.

## Overview

This project implements network applications using sockets in C++.  
It includes both TCP and UDP communication models and demonstrates how data is transmitted between clients and servers.

The goal of this project is to:
- understand network communication principles
- work with TCP and UDP protocols
- implement client-server architecture
- handle multiple clients and message exchange

---

## Features

### TCP
- Reliable connection-oriented communication
- Message exchange between client and server
- Handling multiple clients
- Data persistence (saving messages)

### UDP
- Connectionless communication
- Fast message transmission
- No delivery guarantees
- Lightweight implementation

---

## Tech Stack

- C++
- Sockets (TCP/IP, UDP)
- Linux / Windows

---

## How It Works

### TCP
- Server listens for incoming connections
- Clients connect and exchange messages
- Server processes and optionally stores data

### UDP
- Client sends datagrams to server
- Server receives and processes messages
- No connection setup required

---
