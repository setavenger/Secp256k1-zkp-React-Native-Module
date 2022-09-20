// Header guard
#ifndef SECP256K1_ZKP_REACT_H
#define SECP256K1_ZKP_REACT_H


// Header files
#include <vector>

using namespace std;


// Function prototypes

// Blind sum
vector<uint8_t> blindSum(const uint8_t *positiveBlinds, size_t positiveBlindsSizes[], size_t numberOfPositiveBlinds, const uint8_t *negativeBlinds, size_t negativeBlindsSizes[], size_t numberOfNegativeBlinds);

// Is valid secret key
bool isValidSecretKey(const uint8_t *secretKey, size_t secretKeySize);

// Is valid public key
bool isValidPublicKey(const uint8_t *publicKey, size_t publicKeySize);

// Is valid commit
bool isValidCommit(const uint8_t *commit, size_t commitSize);

// Is valid single-signer signature
bool isValidSingleSignerSignature(const uint8_t *signature, size_t signatureSize);

// Create bulletproof blindless
vector<uint8_t> createBulletproofBlindless(uint8_t *tauX, size_t tauXSize, const uint8_t *tOne, size_t tOneSize, const uint8_t *tTwo, size_t tTwoSize, const uint8_t *commit, size_t commitSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize);

// Rewind bulletproof
tuple<string, vector<uint8_t>, vector<uint8_t>> rewindBulletproof(const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *nonce, size_t nonceSize);

// Verify bulletproof
bool verifyBulletproof(const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *extraCommit, size_t extraCommitSize);

// Public key from data
vector<uint8_t> publicKeyFromData(const uint8_t *data, size_t dataSize);

// Pedersen commit
vector<uint8_t> pedersenCommit(const uint8_t *blind, size_t blindSize, const char *value);

// Pedersen commit sum
vector<uint8_t> pedersenCommitSum(const uint8_t *positiveCommits, size_t positiveCommitsSizes[], size_t numberOfPositiveCommits, const uint8_t *negativeCommits, size_t negativeCommitsSizes[], size_t numberOfNegativeCommits);

// Pedersen commit to public key
vector<uint8_t> pedersenCommitToPublicKey(const uint8_t *commit, size_t commitSize);

// Public key to Pedersen commit
vector<uint8_t> publicKeyToPedersenCommit(const uint8_t *publicKey, size_t publicKeySize);

// Add single-signer signatures
vector<uint8_t> addSingleSignerSignatures(const uint8_t *signatures, size_t signaturesSizes[], size_t numberOfSignatures, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize);

// Verify single-signer signature
bool verifySingleSignerSignature(const uint8_t *signature, size_t signatureSize, const uint8_t *message, size_t messageSize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicKeyTotal, size_t publicKeyTotalSize, bool isPartial);

// Single-signer signature from data
vector<uint8_t> singleSignerSignatureFromData(const uint8_t *data, size_t dataSize);

// Compact single-signer signature
vector<uint8_t> compactSingleSignerSignature(const uint8_t *signature, size_t signatureSize);

// Uncompact single-signer signature
vector<uint8_t> uncompactSingleSignerSignature(const uint8_t *signature, size_t signatureSize);

// Combine public keys
vector<uint8_t> combinePublicKeys(const uint8_t *publicKeys, size_t publicKeysSizes[], size_t numberOfPublicKeys);


#endif
