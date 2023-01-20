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
static void initialize(const uint8_t *seed, size_t seedSize);


// Supporting function implementation

// Blind switch
vector<uint8_t> blindSwitch(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *blind, size_t blindSize, const char *value) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if performing blind switch failed
	vector<uint8_t> result(Secp256k1Zkp::blindSize());
	if(!Secp256k1Zkp::blindSwitch(result.data(), blind, blindSize, value)) {
	
		// Throw error
		throw runtime_error("Performing blind switch failed");
	}
	
	// Return result
	return result;
}

// Blind sum
vector<uint8_t> blindSum(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *positiveBlinds, size_t positiveBlindsSizes[], size_t numberOfPositiveBlinds, const uint8_t *negativeBlinds, size_t negativeBlindsSizes[], size_t numberOfNegativeBlinds) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
bool isValidSecretKey(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *secretKey, size_t secretKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);

	// Check if secret key is not a valid secret key
	if(!Secp256k1Zkp::isValidSecretKey(secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid public key
bool isValidPublicKey(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *publicKey, size_t publicKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if public key is not a valid public key
	if(!Secp256k1Zkp::isValidPublicKey(publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid commit
bool isValidCommit(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *commit, size_t commitSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if commit is not a valid commit
	if(!Secp256k1Zkp::isValidCommit(commit, commitSize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid single-signer signature
bool isValidSingleSignerSignature(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *signature, size_t signatureSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if signature is not a valid single-signer signature
	if(!Secp256k1Zkp::isValidSingleSignerSignature(signature, signatureSize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Create bulletproof blindless
vector<uint8_t> createBulletproof(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *blind, size_t blindSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *privateNonce, size_t privateNonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if creating bulletproof failed
	vector<uint8_t> proof(Secp256k1Zkp::bulletproofProofSize());
	char proofSize[MAX_64_BIT_INTEGER_STRING_LENGTH];
	if(!Secp256k1Zkp::createBulletproof(proof.data(), proofSize, blind, blindSize, value, nonce, nonceSize, privateNonce, privateNonceSize, extraCommit, extraCommitSize, message, messageSize)) {
	
		// Throw error
		throw runtime_error("Creating bulletproof failed");
	}
	
	// Set proof's size to proof size
	proof.resize(strtoull(proofSize, nullptr, 10));
	
	// Return proof
	return proof;
}

// Create bulletproof blindless
vector<uint8_t> createBulletproofBlindless(const uint8_t *contextSeed, size_t contextSeedSize, uint8_t *tauX, size_t tauXSize, const uint8_t *tOne, size_t tOneSize, const uint8_t *tTwo, size_t tTwoSize, const uint8_t *commit, size_t commitSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
tuple<string, vector<uint8_t>, vector<uint8_t>> rewindBulletproof(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *nonce, size_t nonceSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
bool verifyBulletproof(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *extraCommit, size_t extraCommitSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if bulletproof isn't verified
	if(!Secp256k1Zkp::verifyBulletproof(proof, proofSize, commit, commitSize, extraCommit, extraCommitSize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Public key from secret key
vector<uint8_t> publicKeyFromSecretKey(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *secretKey, size_t secretKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if getting public key from secret key failed
	vector<uint8_t> publicKey(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::publicKeyFromSecretKey(publicKey.data(), secretKey, secretKeySize)) {
	
		// Throw error
		throw runtime_error("Getting public key from secret key failed");
	}
	
	// Return public key
	return publicKey;
}

// Public key from data
vector<uint8_t> publicKeyFromData(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *data, size_t dataSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if getting public key from data failed
	vector<uint8_t> publicKey(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::publicKeyFromData(publicKey.data(), data, dataSize)) {
	
		// Throw error
		throw runtime_error("Getting public key from data failed");
	}
	
	// Return public key
	return publicKey;
}

// Uncompress public key
vector<uint8_t> uncompressPublicKey(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *publicKey, size_t publicKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if uncompressing the public key failed
	vector<uint8_t> uncompressedPublicKey(Secp256k1Zkp::uncompressedPublicKeySize());
	if(!Secp256k1Zkp::uncompressPublicKey(uncompressedPublicKey.data(), publicKey, publicKeySize)) {
	
		// Throw error
		throw runtime_error("Uncompressing the public key failed");
	}
	
	// Return uncompressed public key
	return uncompressedPublicKey;
}

// Secret key tweak add
vector<uint8_t> secretKeyTweakAdd(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if performing secret key tweak add failed
	vector<uint8_t> result(Secp256k1Zkp::secretKeySize());
	if(!Secp256k1Zkp::secretKeyTweakAdd(result.data(), secretKey, secretKeySize, tweak, tweakSize)) {
	
		// Throw error
		throw runtime_error("Performing secret key tweak add failed");
	}
	
	// Return result
	return result;
}

// Public key tweak add
vector<uint8_t> publicKeyTweakAdd(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if performing public key tweak add failed
	vector<uint8_t> result(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::publicKeyTweakAdd(result.data(), publicKey, publicKeySize, tweak, tweakSize)) {
	
		// Throw error
		throw runtime_error("Performing public key tweak add failed");
	}
	
	// Return result
	return result;
}

// Secret key tweak multiply
vector<uint8_t> secretKeyTweakMultiply(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if performing secret key tweak multiply failed
	vector<uint8_t> result(Secp256k1Zkp::secretKeySize());
	if(!Secp256k1Zkp::secretKeyTweakMultiply(result.data(), secretKey, secretKeySize, tweak, tweakSize)) {
	
		// Throw error
		throw runtime_error("Performing secret key tweak multiply failed");
	}
	
	// Return result
	return result;
}

// Public key tweak multiply
vector<uint8_t> publicKeyTweakMultiply(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if performing public key tweak multiply failed
	vector<uint8_t> result(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::publicKeyTweakMultiply(result.data(), publicKey, publicKeySize, tweak, tweakSize)) {
	
		// Throw error
		throw runtime_error("Performing public key tweak multiply failed");
	}
	
	// Return result
	return result;
}

// Shared secret key from secret key and public key
vector<uint8_t> sharedSecretKeyFromSecretKeyAndPublicKey(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *publicKey, size_t publicKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if getting shared secret key from secret key and public key failed
	vector<uint8_t> sharedSecretKey(Secp256k1Zkp::secretKeySize());
	if(!Secp256k1Zkp::sharedSecretKeyFromSecretKeyAndPublicKey(sharedSecretKey.data(), secretKey, secretKeySize, publicKey, publicKeySize)) {
	
		// Throw error
		throw runtime_error("Getting shared secret key from secret key and public key failed");
	}
	
	// Return shared secret key
	return sharedSecretKey;
}

// Pedersen commit
vector<uint8_t> pedersenCommit(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *blind, size_t blindSize, const char *value) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
vector<uint8_t> pedersenCommitSum(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *positiveCommits, size_t positiveCommitsSizes[], size_t numberOfPositiveCommits, const uint8_t *negativeCommits, size_t negativeCommitsSizes[], size_t numberOfNegativeCommits) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
vector<uint8_t> pedersenCommitToPublicKey(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *commit, size_t commitSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
vector<uint8_t> publicKeyToPedersenCommit(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *publicKey, size_t publicKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if getting Pedersen commit from public key failed
	vector<uint8_t> commit(Secp256k1Zkp::commitSize());
	if(!Secp256k1Zkp::publicKeyToPedersenCommit(commit.data(), publicKey, publicKeySize)) {
	
		// Throw error
		throw runtime_error("Getting Pedersen commit from public key failed");
	}
	
	// Return commit
	return commit;
}

// Create single-signer signature
vector<uint8_t> createSingleSignerSignature(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *message, size_t messageSize, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *secretNonce, size_t secretNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize, const uint8_t *seed, size_t seedSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if creating single-signer signature failed
	vector<uint8_t> signature(Secp256k1Zkp::singleSignerSignatureSize());
	if(!Secp256k1Zkp::createSingleSignerSignature(signature.data(), message, messageSize, secretKey, secretKeySize, secretNonce, secretNonceSize, publicKey, publicKeySize, publicNonce, publicNonceSize, publicNonceTotal, publicNonceTotalSize, seed, seedSize)) {
	
		// Throw error
		throw runtime_error("Creating single-signer signature failed");
	}
	
	// Return signature
	return signature;
}

// Add single-signer signatures
vector<uint8_t> addSingleSignerSignatures(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *signatures, size_t signaturesSizes[], size_t numberOfSignatures, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
bool verifySingleSignerSignature(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *signature, size_t signatureSize, const uint8_t *message, size_t messageSize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicKeyTotal, size_t publicKeyTotalSize, bool isPartial) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if single-signer signature isn't verified
	if(!Secp256k1Zkp::verifySingleSignerSignature(signature, signatureSize, message, messageSize, publicNonce, publicNonceSize, publicKey, publicKeySize, publicKeyTotal, publicKeyTotalSize, isPartial)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Single-signer signature from data
vector<uint8_t> singleSignerSignatureFromData(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *data, size_t dataSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
vector<uint8_t> compactSingleSignerSignature(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *signature, size_t signatureSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
vector<uint8_t> uncompactSingleSignerSignature(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *signature, size_t signatureSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
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
vector<uint8_t> combinePublicKeys(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *publicKeys, size_t publicKeysSizes[], size_t numberOfPublicKeys) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if combining public keys failed
	vector<uint8_t> result(Secp256k1Zkp::publicKeySize());
	if(!Secp256k1Zkp::combinePublicKeys(result.data(), publicKeys, publicKeysSizes, numberOfPublicKeys)) {
	
		// Throw error
		throw runtime_error("Combining public keys failed");
	}
	
	// Return result
	return result;
}

// Create secret nonce
vector<uint8_t> createSecretNonce(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *seed, size_t seedSize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if creating secure nonce failed
	vector<uint8_t> nonce(Secp256k1Zkp::nonceSize());
	if(!Secp256k1Zkp::createSecretNonce(nonce.data(), seed, seedSize)) {
	
		// Throw error
		throw runtime_error("Creating secure nonce failed");
	}
	
	// Return nonce
	return nonce;
}

// Create message hash signature
vector<uint8_t> createMessageHashSignature(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *messageHash, size_t messageHashSize, const uint8_t *secretKey, size_t secretKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if creating message hash signature failed
	vector<uint8_t> signature(Secp256k1Zkp::maximumMessageHashSignatureSize());
	char signatureSize[MAX_64_BIT_INTEGER_STRING_LENGTH];
	if(!Secp256k1Zkp::createMessageHashSignature(signature.data(), signatureSize, messageHash, messageHashSize, secretKey, secretKeySize)) {
	
		// Throw error
		throw runtime_error("Creating message hash signature failed");
	}
	
	// Set signature's size to signature size
	signature.resize(strtoull(signatureSize, nullptr, 10));
	
	// Return signature
	return signature;
}

// Verify message hash signature
bool verifyMessageHashSignature(const uint8_t *contextSeed, size_t contextSeedSize, const uint8_t *signature, size_t signatureSize, const uint8_t *messageHash, size_t messageHashSize, const uint8_t *publicKey, size_t publicKeySize) {

	// Initialize
	initialize(contextSeed, contextSeedSize);
	
	// Check if message hash signature isn't verified
	if(!Secp256k1Zkp::verifyMessageHashSignature(signature, signatureSize, messageHash, messageHashSize, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Seed size
size_t seedSize() {

	// Return seed size
	return Secp256k1Zkp::seedSize();
}

// Initialize
void initialize(const uint8_t *seed, size_t seedSize) {

	// Check if secp256k1-zkp context isn't initialized
	if(!Secp256k1Zkp::context) {
	
		// Initialize secp256k1-zkp
		Secp256k1Zkp::initialize(seed, seedSize);
		
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
