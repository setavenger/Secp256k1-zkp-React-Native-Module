// Header files
#include <string>
#include "./secp256k1-zkp-react.h"

using namespace std;


// Secp256k1-zkp namespace
namespace Secp256k1Zkp {

	// Header files
	#include "../Secp256k1-zkp-NPM-Package-master/main.cpp"
}

// Function prototypes

// Initialize
static void initialize();


// Supporting function implementation

// Is valid secret key
bool isValidSecretKey(const uint8_t *secretKey, size_t secretKeySize) {

	// Initialize
	initialize();

	// Check if secret key is not a valid secret key
	if(!Secp256k1Zkp::isValidSecretKey(secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Initialize
void initialize() {

	// Check if secp256k1-zkp context isn't initialized
	if(!Secp256k1Zkp::context) {
	
		// Initialize secp256k1-zkp
		Secp256k1Zkp::initialize();
		
		// Check if secp256k1-zkp context was initialized
		if(Secp256k1Zkp::context) {
		
			// Check if registering uninitializing secp256k1-zkp on exit failed
			if(atexit([]() {
			
				// Uninitialize secp256k1-zkp
				Secp256k1Zkp::uninitialize();
			})) {
			
				// Throw error
				throw runtime_error("Registering uninitializing secp256k1-zkp on exit failed");
			}
		}
	}
	
	// Check if initializing secp256k1-zkp failed
	if(!Secp256k1Zkp::context || !Secp256k1Zkp::scratchSpace || !Secp256k1Zkp::generators) {
	
		// Throw error
		throw runtime_error("Initializing secp256k1-zkp failed");
	}
}
