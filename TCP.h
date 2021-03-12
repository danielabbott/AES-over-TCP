#pragma once

/* AES-128-CBC encrypted TCP client and server */

#include <vector>
#include <functional>
#include <string>
#include <array>
#include <cstdint>
#include <utility>
#include "ArrayPointer.h"
#include "HeapArray.h"

class TCPServer;
class TCPClient {
	friend TCPServer;
	TCPClient(int handle, std::array<unsigned char, 16> key);
	int socket_handle = -1;
	std::array<unsigned char, 16> iv;
	std::array<unsigned char, 16> key;

	uintptr_t encryption_context=0, decryption_context=0;

	void create_ssl_objects();

public:
	// ipv6 must be true if the ip string represents an ipv6 address
	TCPClient(std::string const& ip, bool ipv6, unsigned short port, std::array<unsigned char, 16> key);
	~TCPClient();
	bool is_alive() const;

	// Returns data and size
	// Data might be up to 15 bytes bigger than size
	std::pair<HeapArray<unsigned char>, uint32_t> read_message();
	void send_message(ArrayPointer<unsigned char> const&);

	TCPClient(const TCPClient&) = delete;
	TCPClient& operator=(const TCPClient&) = delete;
	TCPClient(TCPClient&&);
	TCPClient& operator=(TCPClient&&);
};

class TCPServer {
	int socket_handle=-1;

public:
	TCPServer(unsigned short port);
	~TCPServer();
	// Blocks until a connection is received
	TCPClient listen(std::array<unsigned char, 16> key);

	TCPServer(const TCPServer&) = delete;
	TCPServer& operator=(const TCPServer&) = delete;
	TCPServer(TCPServer&&);
	TCPServer& operator=(TCPServer&&);
};
