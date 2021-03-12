#include "TCP.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdexcept>
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "Random.h"

using namespace std;

void TCPClient::create_ssl_objects() {
	EVP_CIPHER_CTX * ctx_enc = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX * ctx_dec = EVP_CIPHER_CTX_new();
	if(!ctx_enc || !ctx_dec) {
		throw runtime_error("Error creating encryption/decryption objects");
	}

	if(EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_cbc(), NULL, key.data(), iv.data()) != 1) {
       	throw runtime_error("EVP_DecryptInit_ex error");
	}

	if(EVP_EncryptInit_ex(ctx_enc, EVP_aes_128_cbc(), NULL, key.data(), iv.data()) != 1) {
       	throw runtime_error("EVP_EncryptInit_ex error");
	}

	encryption_context = reinterpret_cast<uintptr_t>(ctx_enc);
	decryption_context = reinterpret_cast<uintptr_t>(ctx_dec);
}

TCPClient::TCPClient(int handle, array<unsigned char, 16> key_) 
: socket_handle(handle), key(key_) {
	// Receive IV

	if(recv(socket_handle, iv.data(), 16, 0) != 16)
	{
		throw exception();
	}
	create_ssl_objects();
}

TCPClient::TCPClient(string const& ip, bool ipv6, unsigned short port, array<unsigned char, 16> key_)
: key(key_)
{
	socket_handle = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (socket_handle == -1)
	{
		throw runtime_error("Error creating client socket");
	}

	if(ipv6) {
		sockaddr_in6 server_address;
		server_address.sin6_family = AF_INET6;
		inet_pton(AF_INET6, ip.c_str(), &server_address.sin6_addr);
		server_address.sin6_port = htons(port);

		if (connect(socket_handle, reinterpret_cast<sockaddr *>(&server_address), sizeof(server_address)) < 0)
		{
			throw runtime_error("Error connecting IPv6 client socket");
		}
	}
	else {
		sockaddr_in server_address;
		server_address.sin_addr.s_addr = inet_addr(ip.c_str());
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(port);

		if (connect(socket_handle, reinterpret_cast<sockaddr *>(&server_address), sizeof(server_address)) < 0)
		{
			throw runtime_error("Error connecting IPv4 client socket");
		}
	}

	// Generate and send IV

	try_create_random(ArrayPointer<uint8_t>(iv.data(), 16));


	if(send(socket_handle, iv.data(), 16, 0) != 16)
	{
		throw runtime_error("Error sending IV data");
	}

	create_ssl_objects();
}

TCPClient::TCPClient(TCPClient&& other)
{
	socket_handle = other.socket_handle;
	other.socket_handle = -1;
}

TCPClient& TCPClient::operator=(TCPClient&& other)
{
	socket_handle = other.socket_handle;
	other.socket_handle = -1;
	return *this;
}

pair<HeapArray<unsigned char>, uint32_t> TCPClient::read_message() {
	#define ERR(x) { \
		socket_handle = -1; \
		throw runtime_error(x); }

	if(socket_handle < 0) {
		ERR("Socket closed");
	}

	uint32_t decrypted_message_length;
	if(recv(socket_handle, &decrypted_message_length, 4, 0) != 4)
	{
		ERR("Error receiving TCP data");
	}

	uint32_t encrypted_message_length;
	if(recv(socket_handle, &encrypted_message_length, 4, 0) != 4)
	{
		ERR("Error receiving TCP data");
	}

	if(decrypted_message_length < 4 || encrypted_message_length < 4)
	{
		ERR("Invalid message length");
	}

	HeapArray<unsigned char> encrypted_data(encrypted_message_length);

	if(recv(socket_handle, encrypted_data.get(), encrypted_data.size(), 0) != static_cast<ssize_t>(encrypted_data.size()))
	{
		ERR("Error receiving TCP data");
	}

	HeapArray<unsigned char> decrypted(encrypted_data.size()+16);

	auto ctx = reinterpret_cast<EVP_CIPHER_CTX *>(decryption_context);

	int actual_decrypted_length;
	if(EVP_DecryptUpdate(ctx, decrypted.data(), &actual_decrypted_length,
			encrypted_data.data(), encrypted_data.size()) != 1) {
		ERR("EVP_DecryptUpdate error");
	}

	int extra;
	if(EVP_DecryptFinal_ex(ctx, &decrypted.data()[actual_decrypted_length], &extra) != 1) {
		ERR("EVP_DecryptFinal_ex error");
	}


	return make_pair(move(decrypted), decrypted_message_length);
}

void TCPClient::send_message(ArrayPointer<unsigned char> const& data)
{
	if(socket_handle < 0) {
		ERR("Socket closed");
	}

	HeapArray<unsigned char> encrypted(data.size() + 15);

	auto ctx = reinterpret_cast<EVP_CIPHER_CTX *>(encryption_context);

    int encrypted_data_length;
   	if(EVP_EncryptUpdate(ctx, encrypted.data(), &encrypted_data_length, data.data(), data.size()) != 1) {
    	ERR("EVP_EncryptUpdate error");
   	}

    int extra_length;
    if(EVP_EncryptFinal_ex(ctx, &encrypted.data()[encrypted_data_length], &extra_length) != 1) {
        ERR("EVP_EncryptFinal_ex error");
    }
    encrypted_data_length += extra_length;

    if(encrypted_data_length > static_cast<int>(encrypted.size())) {
    	ERR("");
    }


    // Send encrypted data

    int unencrypted_size = data.size();
	if(send(socket_handle, &unencrypted_size, 4, 0) != 4)
	{
		ERR("TCP send error");
	}

	if(send(socket_handle, &encrypted_data_length, 4, 0) != 4)
	{
		ERR("TCP send error");
	}

	if(send(socket_handle, encrypted.data(), encrypted_data_length, 0) != encrypted_data_length)
	{
		ERR("TCP send error");
	}

}


TCPClient::~TCPClient()
{
	close(socket_handle);
	if(encryption_context) {
	    EVP_CIPHER_CTX_free(reinterpret_cast<EVP_CIPHER_CTX *>(encryption_context));
	}
	if(decryption_context) {
	    EVP_CIPHER_CTX_free(reinterpret_cast<EVP_CIPHER_CTX *>(decryption_context));
	}
}

bool TCPClient::is_alive() const
{
	return socket_handle >= 0;
}

TCPServer::TCPServer(unsigned short port)
{
	
	socket_handle = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (socket_handle == -1)
	{
		throw runtime_error("Error creating server socket");
	}

	sockaddr_in6 server {};
	server.sin6_family = AF_INET6;
	server.sin6_addr = in6addr_any;
	server.sin6_port = htons( port );
		
	if(bind(socket_handle, reinterpret_cast<sockaddr *>(&server), sizeof(server)) < 0)
	{
		throw runtime_error("Error binding server socket");
	}
	::listen(socket_handle, 1);
}

TCPClient TCPServer::listen(array<unsigned char, 16> key)
{
	if(socket_handle < 0) {
		throw runtime_error("No socket");
	}

	sockaddr_in6 client;
	socklen_t sockaddr_length = sizeof client;
	int id = accept(socket_handle, reinterpret_cast<sockaddr *>(&client), &sockaddr_length);
	if (id == -1)
	{
		throw runtime_error("accept error");
	}
	close(socket_handle);
	socket_handle = -1;
	return TCPClient(id, key);
}

TCPServer::~TCPServer()
{
	if(socket_handle >= 0) {
		close(socket_handle);
	}
}

TCPServer::TCPServer(TCPServer&& other)
{
	socket_handle = other.socket_handle;
	other.socket_handle = -1;
}

TCPServer& TCPServer::operator=(TCPServer&& other)
{
	socket_handle = other.socket_handle;
	other.socket_handle = -1;
	return *this;
}
