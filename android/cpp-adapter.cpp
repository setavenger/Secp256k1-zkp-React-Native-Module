// Header files
#include <iomanip>
#include <jni.h>
#include <memory>
#include <sstream>
#include "secp256k1-zkp-react.h"

using namespace std;


// Constants

// Hex character length
static const size_t HEX_CHARACTER_LENGTH = (sizeof("FF") - sizeof('\0'));

// Bits in a byte
static const int BITS_IN_A_BYTE = 8;


// Function prototypes

// Native blind sum
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeBlindSum(JNIEnv *environment, jclass type, jobjectArray positiveBlinds, jobjectArray negativeBlinds);

// Native is valid secret key
extern "C" JNIEXPORT jboolean JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidSecretKey(JNIEnv *environment, jclass type, jstring secretKey);

// Native is valid public key
extern "C" JNIEXPORT jboolean JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidPublicKey(JNIEnv *environment, jclass type, jstring publicKey);

// Native is valid commit
extern "C" JNIEXPORT jboolean JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidCommit(JNIEnv *environment, jclass type, jstring commit);

// Native is valid single-signer signature
extern "C" JNIEXPORT jboolean JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidSingleSignerSignature(JNIEnv *environment, jclass type, jstring signature);

// Native create bulletproof blindless
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeCreateBulletproofBlindless(JNIEnv *environment, jclass type, jstring tauX, jstring tOne, jstring tTwo, jstring commit, jstring value, jstring nonce, jstring extraCommit, jstring message);

// Native rewind bulletproof
extern "C" JNIEXPORT jobjectArray JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeRewindBulletproof(JNIEnv *environment, jclass type, jstring proof, jstring commit, jstring nonce);

// Native verify bulletproof
extern "C" JNIEXPORT jboolean JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeVerifyBulletproof(JNIEnv *environment, jclass type, jstring proof, jstring commit, jstring extraCommit);

// Native public key from data
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePublicKeyFromData(JNIEnv *environment, jclass type, jstring data);

// Native Pedersen commit
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePedersenCommit(JNIEnv *environment, jclass type, jstring blind, jstring value);

// Native Pedersen commit sum
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePedersenCommitSum(JNIEnv *environment, jclass type, jobjectArray positiveCommits, jobjectArray negativeCommits);

// Native Pedersen commit to public key
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePedersenCommitToPublicKey(JNIEnv *environment, jclass type, jstring commit);

// Native public key to Pedersen commit
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePublicKeyToPedersenCommit(JNIEnv *environment, jclass type, jstring publicKey);

// Native add single-signer signatures
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeAddSingleSignerSignatures(JNIEnv *environment, jclass type, jobjectArray signatures, jstring publicNonceTotal);

// Native verify single-signer signature
extern "C" JNIEXPORT jboolean JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeVerifySingleSignerSignature(JNIEnv *environment, jclass type, jstring signature, jstring message, jstring publicNonce, jstring publicKey, jstring publicKeyTotal, jboolean isPartial);

// Native single-signer signature from data
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeSingleSignerSignatureFromData(JNIEnv *environment, jclass type, jstring data);

// Native compact single-signer signature
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeCompactSingleSignerSignature(JNIEnv *environment, jclass type, jstring signature);

// Native uncompact single-signer signature
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeUncompactSingleSignerSignature(JNIEnv *environment, jclass type, jstring signature);

// Native combine public keys
extern "C" JNIEXPORT jstring JNICALL Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeCombinePublicKeys(JNIEnv *environment, jclass type, jobjectArray publicKeys);

// From hex string
static vector<uint8_t> fromHexString(JNIEnv *environment, jstring hexString);

// To hex string
static jstring toHexString(JNIEnv *environment, const vector<uint8_t> &input);

// Character to number
static uint8_t characterToNumber(char character);

// From bool
static bool fromBool(jboolean input);

// To bool
static jboolean toBool(bool input);


// Supporting function implementation

// Native blind sum
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeBlindSum(JNIEnv *environment, jclass type, jobjectArray positiveBlinds, jobjectArray negativeBlinds) {

	// Try
	try {
	
		// Get number of positive blinds
		const jsize numberOfPositiveBlinds = environment->GetArrayLength(positiveBlinds);
		
		// Initialize positive blinds data and positive blinds sizes
		vector<uint8_t> positiveBlindsData;
		size_t positiveBlindsSizes[numberOfPositiveBlinds];
		
		// Go through all positive blinds
		for(jsize i = 0; i < numberOfPositiveBlinds; ++i) {
		
			// Check if getting blind failed
			const jstring blind = reinterpret_cast<jstring>(environment->GetObjectArrayElement(positiveBlinds, i));
			if(!blind) {
			
				// Throw error
				throw runtime_error("Getting blind failed");
			}
			
			// Get data from blind
			const vector<uint8_t> blindData = fromHexString(environment, blind);
			
			// Append blind data to positive blinds data
			positiveBlindsData.insert(positiveBlindsData.cend(), blindData.cbegin(), blindData.cend());
			
			// Append blind data's size to positive blinds sizes
			positiveBlindsSizes[i] = blindData.size();
		}
		
		// Get number of negative blinds
		const jsize numberOfNegativeBlinds = environment->GetArrayLength(negativeBlinds);
		
		// Initialize negative blinds data and negative blinds sizes
		vector<uint8_t> negativeBlindsData;
		size_t negativeBlindsSizes[numberOfNegativeBlinds];
		
		// Go through all negative blinds
		for(jsize i = 0; i < numberOfNegativeBlinds; ++i) {
		
			// Check if getting blind failed
			const jstring blind = reinterpret_cast<jstring>(environment->GetObjectArrayElement(negativeBlinds, i));
			if(!blind) {
			
				// Throw error
				throw runtime_error("Getting blind failed");
			}
			
			// Get data from blind
			const vector<uint8_t> blindData = fromHexString(environment, blind);
			
			// Append blind data to negative blinds data
			negativeBlindsData.insert(negativeBlindsData.cend(), blindData.cbegin(), blindData.cend());
			
			// Append blind data's size to negative blinds sizes
			negativeBlindsSizes[i] = blindData.size();
		}
		
		// Return performing blind sum
		return toHexString(environment, blindSum(positiveBlindsData.data(), positiveBlindsSizes, numberOfPositiveBlinds, negativeBlindsData.data(), negativeBlindsSizes, numberOfNegativeBlinds));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native is valid secret key
jboolean Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidSecretKey(JNIEnv *environment, jclass type, jstring secretKey) {

	// Try
	try {
	
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(environment, secretKey);

		// Return if secret key is a valid secret key
		return toBool(isValidSecretKey(secretKeyData.data(), secretKeyData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native is valid public key
jboolean Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidPublicKey(JNIEnv *environment, jclass type, jstring publicKey) {

	// Try
	try {
	
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(environment, publicKey);

		// Return if public key is a valid public key
		return toBool(isValidPublicKey(publicKeyData.data(), publicKeyData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native is valid commit
jboolean Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidCommit(JNIEnv *environment, jclass type, jstring commit) {

	// Try
	try {
	
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(environment, commit);

		// Return if commit is a valid commit
		return toBool(isValidCommit(commitData.data(), commitData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native is valid single-signer signature
jboolean Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeIsValidSingleSignerSignature(JNIEnv *environment, jclass type, jstring signature) {

	// Try
	try {
	
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(environment, signature);

		// Return if signature is a valid single-signer signature
		return toBool(isValidSingleSignerSignature(signatureData.data(), signatureData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native create bulletproof blindless
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeCreateBulletproofBlindless(JNIEnv *environment, jclass type, jstring tauX, jstring tOne, jstring tTwo, jstring commit, jstring value, jstring nonce, jstring extraCommit, jstring message) {

	// Try
	try {
	
		// Get data from tau X
		vector<uint8_t> tauXData = fromHexString(environment, tauX);
		
		// Get data from t one
		const vector<uint8_t> tOneData = fromHexString(environment, tOne);
		
		// Get data from t two
		const vector<uint8_t> tTwoData = fromHexString(environment, tTwo);
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(environment, commit);
		
		// Initialize release value data
		auto releaseValueData = [environment, value](const char *valueData) {
		
			// Release value data
			environment->ReleaseStringUTFChars(value, valueData);
		};

		// Check if getting data from value failed
		const unique_ptr<const char,  decltype(releaseValueData)> valueData(environment->GetStringUTFChars(value, nullptr), releaseValueData);
		if(!valueData) {
		
			// Throw error
			throw runtime_error("Getting data from value failed");
		}
		
		// Get data from nonce
		const vector<uint8_t> nonceData = fromHexString(environment, nonce);
		
		// Get data from extra commit
		const vector<uint8_t> extraCommitData = fromHexString(environment, extraCommit);
		
		// Get data from message
		const vector<uint8_t> messageData = fromHexString(environment, message);
		
		// Return creating bulletproof blindless
		return toHexString(environment, createBulletproofBlindless(tauXData.data(), tauXData.size(), tOneData.data(), tOneData.size(), tTwoData.data(), tTwoData.size(), commitData.data(), commitData.size(), valueData.get(), nonceData.data(), nonceData.size(), extraCommitData.data(), extraCommitData.size(), messageData.data(), messageData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native rewind bulletproof
jobjectArray Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeRewindBulletproof(JNIEnv *environment, jclass type, jstring proof, jstring commit, jstring nonce) {

	// Try
	try {
	
		// Get data from proof
		const vector<uint8_t> proofData = fromHexString(environment, proof);
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(environment, commit);
		
		// Get data from nonce
		const vector<uint8_t> nonceData = fromHexString(environment, nonce);

		// Performing rewind bulletproof
		const tuple<string, vector<uint8_t>, vector<uint8_t>> bulletproofData = rewindBulletproof(proofData.data(), proofData.size(), commitData.data(), commitData.size(), nonceData.data(), nonceData.size());
		
		// Check if getting value as a string failed
		const jstring valueString = environment->NewStringUTF(get<0>(bulletproofData).c_str());
		if(!valueString) {
		
			// Throw error
			throw runtime_error("Getting value as a string failed");
		}
		
		// Check if creating result failed
		jobjectArray result = environment->NewObjectArray(3, environment->FindClass("java/lang/String"), nullptr);
		if(!result) {
		
			// Throw error
			throw runtime_error("Creating result failed");
		}
		
		// Set bulletproof data in the result
		environment->SetObjectArrayElement(result, 0, valueString);
		environment->SetObjectArrayElement(result, 1, toHexString(environment, get<1>(bulletproofData)));
		environment->SetObjectArrayElement(result, 2, toHexString(environment, get<2>(bulletproofData)));
		
		// Return result
		return result;
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native verify bulletproof
jboolean Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeVerifyBulletproof(JNIEnv *environment, jclass type, jstring proof, jstring commit, jstring extraCommit) {

	// Try
	try {
	
		// Get data from proof
		const vector<uint8_t> proofData = fromHexString(environment, proof);
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(environment, commit);
		
		// Get data from extra commit
		const vector<uint8_t> extraCommitData = fromHexString(environment, extraCommit);

		// Return if bulletproof is verified
		return toBool(verifyBulletproof(proofData.data(), proofData.size(), commitData.data(), commitData.size(), extraCommitData.data(), extraCommitData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native public key from data
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePublicKeyFromData(JNIEnv *environment, jclass type, jstring data) {

	// Try
	try {
	
		// Get data from data
		const vector<uint8_t> dataData = fromHexString(environment, data);

		// Return getting public key from data
		return toHexString(environment, publicKeyFromData(dataData.data(), dataData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native Pedersen commit
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePedersenCommit(JNIEnv *environment, jclass type, jstring blind, jstring value) {

	// Try
	try {
	
		// Get data from blind
		const vector<uint8_t> blindData = fromHexString(environment, blind);
		
		// Initialize release value data
		auto releaseValueData = [environment, value](const char *valueData) {
		
			// Release value data
			environment->ReleaseStringUTFChars(value, valueData);
		};

		// Check if getting data from value failed
		const unique_ptr<const char,  decltype(releaseValueData)> valueData(environment->GetStringUTFChars(value, nullptr), releaseValueData);
		if(!valueData) {
		
			// Throw error
			throw runtime_error("Getting data from value failed");
		}

		// Return performing Pedersen commit
		return toHexString(environment, pedersenCommit(blindData.data(), blindData.size(), valueData.get()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native Pedersen commit sum
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePedersenCommitSum(JNIEnv *environment, jclass type, jobjectArray positiveCommits, jobjectArray negativeCommits) {

	// Try
	try {
	
		// Get number of positive commits
		const jsize numberOfPositiveCommits = environment->GetArrayLength(positiveCommits);
		
		// Initialize positive commits data and positive commits sizes
		vector<uint8_t> positiveCommitsData;
		size_t positiveCommitsSizes[numberOfPositiveCommits];
		
		// Go through all positive commits
		for(jsize i = 0; i < numberOfPositiveCommits; ++i) {
		
			// Check if getting commit failed
			const jstring commit = reinterpret_cast<jstring>(environment->GetObjectArrayElement(positiveCommits, i));
			if(!commit) {
			
				// Throw error
				throw runtime_error("Getting commit failed");
			}
			
			// Get data from commit
			const vector<uint8_t> commitData = fromHexString(environment, commit);
			
			// Append commit data to positive commits data
			positiveCommitsData.insert(positiveCommitsData.cend(), commitData.cbegin(), commitData.cend());
			
			// Append commit data's size to positive commits sizes
			positiveCommitsSizes[i] = commitData.size();
		}
		
		// Get number of negative commits
		const jsize numberOfNegativeCommits = environment->GetArrayLength(negativeCommits);
		
		// Initialize negative commits data and negative commits sizes
		vector<uint8_t> negativeCommitsData;
		size_t negativeCommitsSizes[numberOfNegativeCommits];
		
		// Go through all negative commits
		for(jsize i = 0; i < numberOfNegativeCommits; ++i) {
		
			// Check if getting commit failed
			const jstring commit = reinterpret_cast<jstring>(environment->GetObjectArrayElement(negativeCommits, i));
			if(!commit) {
			
				// Throw error
				throw runtime_error("Getting commit failed");
			}
			
			// Get data from commit
			const vector<uint8_t> commitData = fromHexString(environment, commit);
			
			// Append commit data to negative commits data
			negativeCommitsData.insert(negativeCommitsData.cend(), commitData.cbegin(), commitData.cend());
			
			// Append commit data's size to negative commits sizes
			negativeCommitsSizes[i] = commitData.size();
		}
		
		// Return performing Pedersen commit sum
		return toHexString(environment, pedersenCommitSum(positiveCommitsData.data(), positiveCommitsSizes, numberOfPositiveCommits, negativeCommitsData.data(), negativeCommitsSizes, numberOfNegativeCommits));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native Pedersen commit to public key
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePedersenCommitToPublicKey(JNIEnv *environment, jclass type, jstring commit) {

	// Try
	try {
	
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(environment, commit);

		// Return getting public key from Pedersen commit
		return toHexString(environment, pedersenCommitToPublicKey(commitData.data(), commitData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native public key to Pedersen commit
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativePublicKeyToPedersenCommit(JNIEnv *environment, jclass type, jstring publicKey) {

	// Try
	try {
	
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(environment, publicKey);

		// Return getting Pedersen commit from public key
		return toHexString(environment, publicKeyToPedersenCommit(publicKeyData.data(), publicKeyData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native add single-signer signatures
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeAddSingleSignerSignatures(JNIEnv *environment, jclass type, jobjectArray signatures, jstring publicNonceTotal) {

	// Try
	try {
	
		// Get number of signatures
		const jsize numberOfSignatures = environment->GetArrayLength(signatures);
		
		// Initialize signatures data and signatures sizes
		vector<uint8_t> signaturesData;
		size_t signaturesSizes[numberOfSignatures];
		
		// Go through all signatures
		for(jsize i = 0; i < numberOfSignatures; ++i) {
		
			// Check if getting signature failed
			const jstring signature = reinterpret_cast<jstring>(environment->GetObjectArrayElement(signatures, i));
			if(!signature) {
			
				// Throw error
				throw runtime_error("Getting signature failed");
			}
			
			// Get data from signature
			const vector<uint8_t> signatureData = fromHexString(environment, signature);
			
			// Append signature data to signatures data
			signaturesData.insert(signaturesData.cend(), signatureData.cbegin(), signatureData.cend());
			
			// Append signature data's size to signatures sizes
			signaturesSizes[i] = signatureData.size();
		}
		
		// Get data from public nonce total
		const vector<uint8_t> publicNonceTotalData = fromHexString(environment, publicNonceTotal);
		
		// Return adding single-signer signatures
		return toHexString(environment, addSingleSignerSignatures(signaturesData.data(), signaturesSizes, numberOfSignatures, publicNonceTotalData.data(), publicNonceTotalData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native verify single-signer signature
jboolean Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeVerifySingleSignerSignature(JNIEnv *environment, jclass type, jstring signature, jstring message, jstring publicNonce, jstring publicKey, jstring publicKeyTotal, jboolean isPartial) {

	// Try
	try {
	
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(environment, signature);
		
		// Get data from message
		const vector<uint8_t> messageData = fromHexString(environment, message);
		
		// Get data from public nonce
		const vector<uint8_t> publicNonceData = publicNonce ? fromHexString(environment, publicNonce) : vector<uint8_t>();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(environment, publicKey);
		
		// Get data from public key total
		const vector<uint8_t> publicKeyTotalData = fromHexString(environment, publicKeyTotal);

		// Return if single-signer signature is verified
		return toBool(verifySingleSignerSignature(signatureData.data(), signatureData.size(), messageData.data(), messageData.size(), publicNonce ? publicNonceData.data() : nullptr, publicNonceData.size(), publicKeyData.data(), publicKeyData.size(), publicKeyTotalData.data(), publicKeyTotalData.size(), fromBool(isPartial)));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// Native single-signer signature from data
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeSingleSignerSignatureFromData(JNIEnv *environment, jclass type, jstring data) {

	// Try
	try {
	
		// Get data from data
		const vector<uint8_t> dataData = fromHexString(environment, data);

		// Return getting single-signer signature from data
		return toHexString(environment, singleSignerSignatureFromData(dataData.data(), dataData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native compact single-signer signature
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeCompactSingleSignerSignature(JNIEnv *environment, jclass type, jstring signature) {

	// Try
	try {
	
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(environment, signature);

		// Return compacting single-signer signature
		return toHexString(environment, compactSingleSignerSignature(signatureData.data(), signatureData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native uncompact single-signer signature
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeUncompactSingleSignerSignature(JNIEnv *environment, jclass type, jstring signature) {

	// Try
	try {
	
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(environment, signature);

		// Return uncompacting single-signer signature
		return toHexString(environment, uncompactSingleSignerSignature(signatureData.data(), signatureData.size()));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return nothing
		return nullptr;
	}
}

// Native combine public keys
jstring Java_com_secp256k1zkpreact_Secp256k1ZkpReactModule_nativeCombinePublicKeys(JNIEnv *environment, jclass type, jobjectArray publicKeys) {

	// Try
	try {
	
		// Get number of public keys
		const jsize numberOfPublicKeys = environment->GetArrayLength(publicKeys);
		
		// Initialize public keys data and public keys sizes
		vector<uint8_t> publicKeysData;
		size_t publicKeysSizes[numberOfPublicKeys];
		
		// Go through all public keys
		for(jsize i = 0; i < numberOfPublicKeys; ++i) {
		
			// Check if getting public key failed
			const jstring publicKey = reinterpret_cast<jstring>(environment->GetObjectArrayElement(publicKeys, i));
			if(!publicKey) {
			
				// Throw error
				throw runtime_error("Getting public key failed");
			}
			
			// Get data from public key
			const vector<uint8_t> publicKeyData = fromHexString(environment, publicKey);
			
			// Append public key data to public keys data
			publicKeysData.insert(publicKeysData.cend(), publicKeyData.cbegin(), publicKeyData.cend());
			
			// Append public key data's size to public keys sizes
			publicKeysSizes[i] = publicKeyData.size();
		}
		
		// Return combining public keys
		return toHexString(environment, combinePublicKeys(publicKeysData.data(), publicKeysSizes, numberOfPublicKeys));
	}
	
	// Catch errors
	catch(const exception &error) {
	
		// Check if throwing error failed
		if(environment->ThrowNew(environment->FindClass("java/lang/RuntimeException"), error.what() ? error.what() : "")) {
		
			// Exit
			exit(0);
		}
		
		// Return false
		return JNI_FALSE;
	}
}

// From hex string
vector<uint8_t> fromHexString(JNIEnv *environment, jstring hexString) {

	// Initialize release input
	auto releaseInput = [environment, hexString](const char *input) {
	
		// Release input
		environment->ReleaseStringUTFChars(hexString, input);
	};

	// Check if getting input from hex string failed
	const unique_ptr<const char,  decltype(releaseInput)> input(environment->GetStringUTFChars(hexString, nullptr), releaseInput);
	if(!input) {
	
		// Throw error
		throw runtime_error("Getting input from hex string failed");
	}
	
	// Get input length
	const size_t inputLength = strlen(input.get());
	
	// Check if input length is invalid
	if(inputLength % HEX_CHARACTER_LENGTH) {
	
		// Throw error
		throw runtime_error("Input length is invalid");
	}
	
	// Initialize result
	vector<uint8_t> result(inputLength / HEX_CHARACTER_LENGTH);
	
	// Go through all character pairs in the input
	for(size_t i = 0; i < inputLength; i += HEX_CHARACTER_LENGTH) {
	
		// Set value in result
		result[i / HEX_CHARACTER_LENGTH] = (characterToNumber(input.get()[i]) << BITS_IN_A_BYTE / 2) | characterToNumber(input.get()[i + 1]);
	}
	
	// Return result
	return result;
}

// To hex string
jstring toHexString(JNIEnv *environment, const vector<uint8_t> &input) {

	// Initialize result
	ostringstream result;
	
	// Configure result
	result << hex << setfill('0');
	
	// Go through all bytes in the input
	for(const uint8_t byte : input) {
	
		// Append byte to result
		result << setw(HEX_CHARACTER_LENGTH) << static_cast<unsigned>(byte);
	}
	
	// Check if getting result as a string failed
	const jstring resultString = environment->NewStringUTF(result.str().c_str());
	if(!resultString) {
	
		// Throw error
		throw runtime_error("Getting result as a string failed");
	}
	
	// Return result string
	return resultString;
}

// Character to number
uint8_t characterToNumber(char character) {

	// Check character
	switch(character) {
	
		// Zero
		case '0':
		
			// Return number
			return 0;
		
		// One
		case '1':
		
			// Return number
			return 1;
		
		// Two
		case '2':
		
			// Return number
			return 2;
		
		// Three
		case '3':
		
			// Return number
			return 3;
		
		// Four
		case '4':
		
			// Return number
			return 4;
		
		// Five
		case '5':
		
			// Return number
			return 5;
		
		// Six
		case '6':
		
			// Return number
			return 6;
		
		// Seven
		case '7':
		
			// Return number
			return 7;
		
		// Eight
		case '8':
		
			// Return number
			return 8;
		
		// Nine
		case '9':
		
			// Return number
			return 9;
		
		// A
		case 'a':
		case 'A':
		
			// Return number
			return 10;
		
		// B
		case 'b':
		case 'B':
		
			// Return number
			return 11;
		
		// C
		case 'c':
		case 'C':
		
			// Return number
			return 12;
		
		// D
		case 'd':
		case 'D':
		
			// Return number
			return 13;
		
		// E
		case 'e':
		case 'E':
		
			// Return number
			return 14;
		
		// F
		case 'f':
		case 'F':
		
			// Return number
			return 15;
		
		// Default
		default:
		
			// Throw error
			throw runtime_error("Getting character as a number failed");
	}
}

// From bool
bool fromBool(jboolean input) {

	// Return input as a bool
	return input == JNI_TRUE;
}

// To bool
jboolean toBool(bool input) {

	// Return input as a bool
	return input ? JNI_TRUE : JNI_FALSE;
}
