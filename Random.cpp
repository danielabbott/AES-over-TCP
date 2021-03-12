#include "Random.h"

#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/rand.h>
#include <stdexcept>

using namespace std;

void try_create_random(ArrayPointer<uint8_t> data) {
	for(int attempts = 0; attempts < 3; attempts++) {
		int success = RAND_bytes(data.get(), data.size());
		if(success == 1) {
			return;
		}
	}
	throw runtime_error("RAND_bytes error");
}