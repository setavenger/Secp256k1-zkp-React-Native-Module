// Header files
#include <string>
#include "./secp256k1-zkp-react.h"

using namespace std;


// Secp256k1-zkp namespace
namespace Secp256k1Zkp {

	// Header files
	#include "../Secp256k1-zkp-NPM-Package-master/main.cpp"
}


// Constants

// Max 64-bit integer string length
static const size_t MAX_64_BIT_INTEGER_STRING_LENGTH = sizeof("18446744073709551615");


// Function prototypes

// Initialize
static void initialize();


// Supporting function implementation

// Blind sum
vector<uint8_t> blindSum(const uint8_t *positiveBlinds, size_t positiveBlindsSizes[], size_t numberOfPositiveBlinds, const uint8_t *negativeBlinds, size_t negativeBlindsSizes[], size_t numberOfNegativeBlinds) {

	// Initialize
	initialize();
	
	// Initialize blinds and blinds sizes
	vector<uint8_t> blinds;
	vector<size_t> blindsSizes(numberOfPositiveBlinds + numberOfNegativeBlinds);
	
	// Go through all positive blinds
	const uint8_t *blind = positiveBlinds;
	for(size_t i = 0; i < numberOfPositiveBlinds; ++i) {
	
		// Append blind buffer to blinds
		blinds.insert(blinds.cend(), blind, blind + positiveBlindsSizes[i]);
		
		// Append blind's size to blinds sizes
		blindsSizes[i] = positiveBlindsSizes[i];
		
		// Go to next blind
		blind += positiveBlindsSizes[i];
	}
	
	// Go through all negative blinds
	blind = negativeBlinds;
	for(size_t i = 0; i < numberOfNegativeBlinds; ++i) {
	
		// Append blind buffer to blinds
		blinds.insert(blinds.cend(), blind, blind + negativeBlindsSizes[i]);
		
		// Append blind's size to blinds sizes
		blindsSizes[i + numberOfPositiveBlinds] = negativeBlindsSizes[i];
		
		// Go to next blind
		blind += negativeBlindsSizes[i];
	}
	
	// Check if performing blind sum failed
	vector<uint8_t> result(Secp256k1Zkp::blindSize());
	if(!Secp256k1Zkp::blindSum(result.data(), blinds.data(), blindsSizes.data(), numberOfPositiveBlinds + numberOfNegativeBlinds, numberOfPositiveBlinds)) {
	
		// Throw error
		throw runtime_error("Performing blind sum failed");
	}
	
	// Return result
	return result;
}

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

// Is valid public key
bool isValidPublicKey(const uint8_t *publicKey, size_t publicKeySize) {

	// Initialize
	initialize();
	
	// Check if public key is not a valid public key
	if(!Secp256k1Zkp::isValidPublicKey(publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid commit
bool isValidCommit(const uint8_t *commit, size_t commitSize) {

	// Initialize
	initialize();
	
	// Check if commit is not a valid commit
	if(!Secp256k1Zkp::isValidCommit(commit, commitSize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid single-signer signature
bool isValidSingleSignerSignature(const uint8_t *signature, size_t signatureSize) {

	// Initialize
	initialize();
	
	// Check if signature is not a valid single-signer signature
	if(!Secp256k1Zkp::isValidSingleSignerSignature(signature, signatureSize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Create bulletproof blindless
vector<uint8_t> createBulletproofBlindless(uint8_t *tauX, size_t tauXSize, const uint8_t *tOne, size_t tOneSize, const uint8_t *tTwo, size_t tTwoSize, const uint8_t *commit, size_t commitSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize) {

	// Initialize
	initialize();
	
	// Check if creating bulletproof blindless failed
	vector<uint8_t> proof(Secp256k1Zkp::bulletproofProofSize());
	char proofSize[MAX_64_BIT_INTEGER_STRING_LENGTH];
	if(!Secp256k1Zkp::createBulletproofBlindless(proof.data(), proofSize, tauX, tauXSize, tOne, tOneSize, tTwo, tTwoSize, commit, commitSize, value, nonce, nonceSize, extraCommit, extraCommitSize, message, messageSize)) {
	
		// Throw error
		throw runtime_error("Creating bulletproof blindless failed");
	}
	
	// Set proof's size to proof size
	proof.resize(strtoull(proofSize, nullptr, 10));
	
	// Return proof
	return proof;
}

// Rewind bulletproof
tuple<string, vector<uint8_t>, vector<uint8_t>> rewindBulletproof(const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *nonce, size_t nonceSize) {

	// Initialize
	initialize();
	
	// Check if performing rewind bulletproof failed
	char value[MAX_64_BIT_INTEGER_STRING_LENGTH];
	vector<uint8_t> blind(Secp256k1Zkp::blindSize());
	vector<uint8_t> message(Secp256k1Zkp::bulletproofMessageSize());
	if(!Secp256k1Zkp::rewindBulletproof(value, blind.data(), message.data(), proof, proofSize, commit, commitSize, nonce, nonceSize)) {
	
		// Throw error
		throw runtime_error("Performing rewind bulletproof failed");
	}
	
	// Return bulletproof data
	return {value, blind, message};
}

// Verify bulletproof
bool verifyBulletproof(const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *extraCommit, size_t extraCommitSize) {

	// Initialize
	initialize();
	
	// Check if bulletproof isn't verified
	if(!Secp256k1Zkp::verifyBulletproof(proof, proofSize, commit, commitSize, extraCommit, extraCommitSize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Public key from data
vector<uint8_t> publicKeyFromData(const uint8_t *data, size_t dataSize) {

	// Initialize
	initialize();
	
	// Check if getting public key from data failed
	vector<uint8_t> publicKey(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::publicKeyFromData(publicKey.data(), data, dataSize)) {
	
		// Throw error
		throw runtime_error("Getting public key from data failed");
	}
	
	// Return public key
	return publicKey;
}

// Pedersen commit
vector<uint8_t> pedersenCommit(const uint8_t *blind, size_t blindSize, const char *value) {

	// Initialize
	initialize();
	
	// Check if performing Pedersen commit failed
	vector<uint8_t> result(Secp256k1Zkp::commitSize());
	if(!Secp256k1Zkp::pedersenCommit(result.data(), blind, blindSize, value)) {
	
		// Throw error
		throw runtime_error("Performing Pedersen commit failed");
	}
	
	// Return result
	return result;
}

// Pedersen commit sum
vector<uint8_t> pedersenCommitSum(const uint8_t *positiveCommits, size_t positiveCommitsSizes[], size_t numberOfPositiveCommits, const uint8_t *negativeCommits, size_t negativeCommitsSizes[], size_t numberOfNegativeCommits) {

	// Initialize
	initialize();
	
	// Check if performing Pedersen commit sum failed
	vector<uint8_t> result(Secp256k1Zkp::commitSize());
	if(!Secp256k1Zkp::pedersenCommitSum(result.data(), positiveCommits, positiveCommitsSizes, numberOfPositiveCommits, negativeCommits, negativeCommitsSizes, numberOfNegativeCommits)) {
	
		// Throw error
		throw runtime_error("Performing Pedersen commit sum failed");
	}
	
	// Return result
	return result;
}

// Pedersen commit to public key
vector<uint8_t> pedersenCommitToPublicKey(const uint8_t *commit, size_t commitSize) {

	// Initialize
	initialize();
	
	// Check if getting public key from Pedersen commit failed
	vector<uint8_t> publicKey(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::pedersenCommitToPublicKey(publicKey.data(), commit, commitSize)) {
	
		// Throw error
		throw runtime_error("Getting public key from Pedersen commit failed");
	}
	
	// Return public key
	return publicKey;
}

// Public key to Pedersen commit
vector<uint8_t> publicKeyToPedersenCommit(const uint8_t *publicKey, size_t publicKeySize) {

	// Initialize
	initialize();
	
	// Check if getting Pedersen commit from public key failed
	vector<uint8_t> commit(Secp256k1Zkp::commitSize());
	if(!Secp256k1Zkp::publicKeyToPedersenCommit(commit.data(), publicKey, publicKeySize)) {
	
		// Throw error
		throw runtime_error("Getting Pedersen commit from public key failed");
	}
	
	// Return commit
	return commit;
}

// Add single-signer signatures
vector<uint8_t> addSingleSignerSignatures(const uint8_t *signatures, size_t signaturesSizes[], size_t numberOfSignatures, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize) {

	// Initialize
	initialize();
	
	// Check if adding single-signer signatures failed
	vector<uint8_t> result(Secp256k1Zkp::singleSignerSignatureSize());
	if(!Secp256k1Zkp::addSingleSignerSignatures(result.data(), signatures, signaturesSizes, numberOfSignatures, publicNonceTotal, publicNonceTotalSize)) {
	
		// Throw error
		throw runtime_error("Adding single-signer signatures failed");
	}
	
	// Return result
	return result;
}

// Verify single-signer signature
bool verifySingleSignerSignature(const uint8_t *signature, size_t signatureSize, const uint8_t *message, size_t messageSize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicKeyTotal, size_t publicKeyTotalSize, bool isPartial) {

	// Initialize
	initialize();
	
	// Check if single-signer signature isn't verified
	if(!Secp256k1Zkp::verifySingleSignerSignature(signature, signatureSize, message, messageSize, publicNonce, publicNonceSize, publicKey, publicKeySize, publicKeyTotal, publicKeyTotalSize, isPartial)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Single-signer signature from data
vector<uint8_t> singleSignerSignatureFromData(const uint8_t *data, size_t dataSize) {

	// Initialize
	initialize();
	
	// Check if getting single-signer signature from data failed
	vector<uint8_t> signature(Secp256k1Zkp::singleSignerSignatureSize());
	if(!Secp256k1Zkp::singleSignerSignatureFromData(signature.data(), data, dataSize)) {
	
		// Throw error
		throw runtime_error("Getting single-signer signature from data failed");
	}
	
	// Return signature
	return signature;
}

// Compact single-signer signature
vector<uint8_t> compactSingleSignerSignature(const uint8_t *signature, size_t signatureSize) {

	// Initialize
	initialize();
	
	// Check if compacting single-signer signature failed
	vector<uint8_t> result(Secp256k1Zkp::singleSignerSignatureSize());
	if(!Secp256k1Zkp::compactSingleSignerSignature(result.data(), signature, signatureSize)) {
	
		// Throw error
		throw runtime_error("Compacting single-signer signature failed");
	}
	
	// Return result
	return result;
}

// Uncompact single-signer signature
vector<uint8_t> uncompactSingleSignerSignature(const uint8_t *signature, size_t signatureSize) {

	// Initialize
	initialize();
	
	// Check if uncompacting single-signer signature failed
	vector<uint8_t> result(Secp256k1Zkp::uncompactSingleSignerSignatureSize());
	if(!Secp256k1Zkp::uncompactSingleSignerSignature(result.data(), signature, signatureSize)) {
	
		// Throw error
		throw runtime_error("Uncompacting single-signer signature failed");
	}
	
	// Return result
	return result;
}

// Combine public keys
vector<uint8_t> combinePublicKeys(const uint8_t *publicKeys, size_t publicKeysSizes[], size_t numberOfPublicKeys) {

	// Initialize
	initialize();
	
	// Check if combining public keys failed
	vector<uint8_t> result(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::combinePublicKeys(result.data(), publicKeys, publicKeysSizes, numberOfPublicKeys)) {
	
		// Throw error
		throw runtime_error("Combining public keys failed");
	}
	
	// Return result
	return result;
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
			
				// Uninitialize secp256k1-zkp
				Secp256k1Zkp::uninitialize();
			
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
