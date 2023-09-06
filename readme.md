# VPN Project

## Table of Contents
- [Introduction](#introduction)
- [How It Works](#how-it-works)
- [Future Changes](#future-changes)

## Introduction
The VPN project is a simple client-server application designed to establish virtual networks independently of each other. It uses sockets, pytun, threads, and select to manage connections efficiently. Additionally, it comes with a CLI (Command Line Interface) to provide a user-friendly way to interact with the VPN.

## How It Works
### Server
When a client connects to the server, the first packet it sends should contain the user's credentials. The server responds with information for the virtual interface and a hash key for packet encryption. Each client request is associated with a virtual network, and the server routes packets to the intended recipient's connection. Notably, the server does not require a virtual network interface.

### Client
The client establishes a connection with the server, sending user credentials as its initial packet. Once connected, the client receives information about the virtual interface and an encryption key. Any subsequent data sent by the client is routed through the virtual network.

## Future Changes
This project is continually evolving, and future changes and improvements are planned:
- [x] **Encryption**: Implemented encryption using the provided encryption key from the server.
- [x] **Data Structuring**: Improved the data structuring within the application, utilizing a MongoDB database to store information.
- [x] **Usage Statistics**: Display the amount of data transferred for each user account.
- [x] **Enhanced Authentication**: Strengthened authentication methods, moving away from plaintext passwords.
- [ ] **Absolute Redirection**: Allow for the complete redirection of user connections, essentially functioning as a VPN.
- [x] **Multithreading**: Utilized more threads to increase data processing speed when handling user data.

Feel free to contribute, offer suggestions, or provide feedback to help enhance this VPN project!
