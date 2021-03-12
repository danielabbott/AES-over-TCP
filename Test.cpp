#include "TCP.h"
#include <cstring>
#include <iostream>

using namespace std;

int main() {
	array<unsigned char, 16> key;
	memset(key.data(), 33, 16);
	unsigned short port = 50000;
	try {
		TCPClient tcp("127.0.0.1", false, port, key);
		// TCPClient tcp("::1", true, port, key);
		cout << "Made connection.\n";
		char send_data[] = {'h','e','l','l','o', 0};
		tcp.send_message(ArrayPointer<unsigned char>(
			reinterpret_cast<unsigned char *>(send_data), sizeof send_data
		));
		auto [received_data, received_data_size] = tcp.read_message();
		received_data.get()[received_data_size-1] = 0;
		cout << "Client received: " << received_data.get() << '\n';
	}
	catch(exception const& e) {
		cout << e.what() << '\n';
		cout << "Could not connect to server. Listening..\n";

		TCPServer s(port);
		TCPClient c = s.listen(key);
		cout << "Server got connection\n";

		auto [received_data, received_data_size] = c.read_message();
		received_data.get()[received_data_size-1] = 0;
		cout << "Server received: " << received_data.get() << '\n';
		char send_data[] = {'b','y','e',0};
		c.send_message(ArrayPointer<unsigned char>(
			reinterpret_cast<unsigned char *>(send_data), sizeof send_data
		));
	}
	return 0;
}