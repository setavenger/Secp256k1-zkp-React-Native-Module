// Header files
#import <Foundation/Foundation.h>
#import <iomanip>
#import <Security/Security.h>
#import <sstream>
#import "secp256k1-zkp-react.h"
#import "./Secp256k1ZkpReact.h"

using namespace std;


// Constants

// Hex character length
static const size_t HEX_CHARACTER_LENGTH = (sizeof("FF") - sizeof('\0'));

// Bits in a byte
static const int BITS_IN_A_BYTE = 8;


// Global variables

// Context seed
static vector<uint8_t> contextSeed;


// Function prototypes

// From hex string
static vector<uint8_t> fromHexString(const NSString *hexString);

// To hex string
static const NSString *toHexString(const vector<uint8_t> &input);

// Character to number
static uint8_t characterToNumber(char character);

// From bool
static bool fromBool(const NSNumber *input);

// To bool
static const NSNumber *toBool(bool input);

// Initialize context seed
static void initializeContextSeed();


// Implementations

// Secp256k1-zkp React implementation
@implementation Secp256k1ZkpReact

// Export module
RCT_EXPORT_MODULE()

// Blind switch
RCT_EXPORT_METHOD(blindSwitch:(nonnull NSString *)blind
	withValue:(nonnull NSString *)value
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from blind
		const vector<uint8_t> blindData = fromHexString(blind);
		
		// Check if getting data from value failed
		const char *valueData = [value UTF8String];
		if(!valueData) {

			// Throw error
			throw runtime_error("Getting data from value failed");
		}
		
		// Resolve performing blind switch
		resolve(toHexString(blindSwitch(contextSeed.data(), contextSeed.size(), blindData.data(), blindData.size(), valueData)));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Blind sum
RCT_EXPORT_METHOD(blindSum:(nonnull NSArray *)positiveBlinds
	withNegativeBlinds:(nonnull NSArray *)negativeBlinds
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get number of positive blinds
		const NSUInteger numberOfPositiveBlinds = [positiveBlinds count];
	
		// Initialize positive blinds data and positive blinds sizes
		vector<uint8_t> positiveBlindsData;
		size_t positiveBlindsSizes[numberOfPositiveBlinds];
		
		// Go through all positive blinds
		size_t i = 0;
		for(const NSString *blind in positiveBlinds) {
		
			// Get data from blind
			const vector<uint8_t> blindData = fromHexString(blind);
			
			// Append blind data to positive blinds data
			positiveBlindsData.insert(positiveBlindsData.cend(), blindData.cbegin(), blindData.cend());
			
			// Append blind data's size to positive blinds sizes
			positiveBlindsSizes[i] = blindData.size();
			
			// Increment index
			++i;
		}
		
		// Get number of negative blinds
		const NSUInteger numberOfNegativeBlinds = [negativeBlinds count];
		
		// Initialize negative blinds data and negative blinds sizes
		vector<uint8_t> negativeBlindsData;
		size_t negativeBlindsSizes[numberOfNegativeBlinds];
		
		// Go through all negative blinds
		i = 0;
		for(const NSString *blind in negativeBlinds) {
		
			// Get data from blind
			const vector<uint8_t> blindData = fromHexString(blind);
			
			// Append blind data to negative blinds data
			negativeBlindsData.insert(negativeBlindsData.cend(), blindData.cbegin(), blindData.cend());
			
			// Append blind data's size to negative blinds sizes
			negativeBlindsSizes[i] = blindData.size();
			
			// Increment index
			++i;
		}
		
		//Resolve performing blind sum
		resolve(toHexString(blindSum(contextSeed.data(), contextSeed.size(), positiveBlindsData.data(), positiveBlindsSizes, numberOfPositiveBlinds, negativeBlindsData.data(), negativeBlindsSizes, numberOfNegativeBlinds)));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Is valid secret key
RCT_EXPORT_METHOD(isValidSecretKey:(nonnull NSString *)secretKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {

		// Initialize context seed
		initializeContextSeed();
		
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(secretKey);

		// Resolve if secret key is a valid secret key
		resolve(toBool(isValidSecretKey(contextSeed.data(), contextSeed.size(), secretKeyData.data(), secretKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Is valid public key
RCT_EXPORT_METHOD(isValidPublicKey:(nonnull NSString *)publicKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);

		// Resolve if public key is a valid public key
		resolve(toBool(isValidPublicKey(contextSeed.data(), contextSeed.size(), publicKeyData.data(), publicKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Is valid commit
RCT_EXPORT_METHOD(isValidCommit:(nonnull NSString *)commit
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(commit);

		// Resolve if commit is a valid commit
		resolve(toBool(isValidCommit(contextSeed.data(), contextSeed.size(), commitData.data(), commitData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Is valid single-signer signature
RCT_EXPORT_METHOD(isValidSingleSignerSignature:(nonnull NSString *)signature
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(signature);

		// Resolve if signature is a valid single-signer signature
		resolve(toBool(isValidSingleSignerSignature(contextSeed.data(), contextSeed.size(), signatureData.data(), signatureData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Create bulletproof
RCT_EXPORT_METHOD(createBulletproof:(nonnull NSString *)blind
	withValue:(nonnull NSString *)value
	withNonce:(nonnull NSString *)nonce
	withPrivateNonce:(nonnull NSString *)privateNonce
	withExtraCommit:(nonnull NSString *)extraCommit
	withMessage:(nonnull NSString *)message
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from blind
		const vector<uint8_t> blindData = fromHexString(blind);
		
		// Check if getting data from value failed
		const char *valueData = [value UTF8String];
		if(!valueData) {

			// Throw error
			throw runtime_error("Getting data from value failed");
		}
		
		// Get data from nonce
		const vector<uint8_t> nonceData = fromHexString(nonce);
		
		// Get data from private nonce
		const vector<uint8_t> privateNonceData = fromHexString(privateNonce);
		
		// Get data from extra commit
		const vector<uint8_t> extraCommitData = fromHexString(extraCommit);
		
		// Get data from message
		const vector<uint8_t> messageData = fromHexString(message);

		// Resolve creating bulletproof
		resolve(toHexString(createBulletproof(contextSeed.data(), contextSeed.size(), blindData.data(), blindData.size(), valueData, nonceData.data(), nonceData.size(), privateNonceData.data(), privateNonceData.size(), extraCommitData.data(), extraCommitData.size(), messageData.data(), messageData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Create bulletproof blindless
RCT_EXPORT_METHOD(createBulletproofBlindless:(nonnull NSString *)tauX
	withTOne:(nonnull NSString *)tOne
	withTTwo:(nonnull NSString *)tTwo
	withCommit:(nonnull NSString *)commit
	withValue:(nonnull NSString *)value
	withNonce:(nonnull NSString *)nonce
	withExtraCommit:(nonnull NSString *)extraCommit
	withMessage:(nonnull NSString *)message
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from tau X
		vector<uint8_t> tauXData = fromHexString(tauX);
		
		// Get data from t one
		const vector<uint8_t> tOneData = fromHexString(tOne);
		
		// Get data from t two
		const vector<uint8_t> tTwoData = fromHexString(tTwo);
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(commit);
		
		// Check if getting data from value failed
		const char *valueData = [value UTF8String];
		if(!valueData) {

			// Throw error
			throw runtime_error("Getting data from value failed");
		}
		
		// Get data from nonce
		const vector<uint8_t> nonceData = fromHexString(nonce);
		
		// Get data from extra commit
		const vector<uint8_t> extraCommitData = fromHexString(extraCommit);
		
		// Get data from message
		const vector<uint8_t> messageData = fromHexString(message);

		// Resolve creating bulletproof blindless
		resolve(toHexString(createBulletproofBlindless(contextSeed.data(), contextSeed.size(), tauXData.data(), tauXData.size(), tOneData.data(), tOneData.size(), tTwoData.data(), tTwoData.size(), commitData.data(), commitData.size(), valueData, nonceData.data(), nonceData.size(), extraCommitData.data(), extraCommitData.size(), messageData.data(), messageData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Rewind bulletproof
RCT_EXPORT_METHOD(rewindBulletproof:(nonnull NSString *)proof
	withCommit:(nonnull NSString *)commit
	withNonce:(nonnull NSString *)nonce
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from proof
		const vector<uint8_t> proofData = fromHexString(proof);
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(commit);
		
		// Get data from nonce
		const vector<uint8_t> nonceData = fromHexString(nonce);

		// Performing rewind bulletproof
		const tuple<string, vector<uint8_t>, vector<uint8_t>> bulletproofData = rewindBulletproof(contextSeed.data(), contextSeed.size(), proofData.data(), proofData.size(), commitData.data(), commitData.size(), nonceData.data(), nonceData.size());
		
		// Check if getting value as a string failed
		const NSString *valueString = [NSString stringWithUTF8String:get<0>(bulletproofData).c_str()];
		if(!valueString) {

			// Throw error
			throw runtime_error("Getting value as a string failed");
		}
		
		// Check if creating result failed
		const NSDictionary *result = [NSDictionary dictionaryWithObjectsAndKeys:valueString, @"Value", toHexString(get<1>(bulletproofData)), @"Blind", toHexString(get<2>(bulletproofData)), @"Message", nil];
		if(!result) {
		
			// Throw error
			throw runtime_error("Creating result failed");
		}
		
		// Resolve result
		resolve(result);
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Verify bulletproof
RCT_EXPORT_METHOD(verifyBulletproof:(nonnull NSString *)proof
	withCommit:(nonnull NSString *)commit
	withExtraCommit:(nonnull NSString *)extraCommit
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from proof
		const vector<uint8_t> proofData = fromHexString(proof);
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(commit);
		
		// Get data from extra commit
		const vector<uint8_t> extraCommitData = fromHexString(extraCommit);

		// Return if bulletproof is verified
		resolve(toBool(verifyBulletproof(contextSeed.data(), contextSeed.size(), proofData.data(), proofData.size(), commitData.data(), commitData.size(), extraCommitData.data(), extraCommitData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Public key from secret key
RCT_EXPORT_METHOD(publicKeyFromSecretKey:(nonnull NSString *)secretKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(secretKey);

		// Resolve getting public key from secret key
		resolve(toHexString(publicKeyFromSecretKey(contextSeed.data(), contextSeed.size(), secretKeyData.data(), secretKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Public key from data
RCT_EXPORT_METHOD(publicKeyFromData:(nonnull NSString *)data
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from data
		const vector<uint8_t> dataData = fromHexString(data);

		// Resolve getting public key from data
		resolve(toHexString(publicKeyFromData(contextSeed.data(), contextSeed.size(), dataData.data(), dataData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Uncompress public key
RCT_EXPORT_METHOD(uncompressPublicKey:(nonnull NSString *)publicKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);

		// Resolve uncompressing the public key
		resolve(toHexString(uncompressPublicKey(contextSeed.data(), contextSeed.size(), publicKeyData.data(), publicKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Secret key tweak add
RCT_EXPORT_METHOD(secretKeyTweakAdd:(nonnull NSString *)secretKey
	withTweak:(nonnull NSString *)tweak
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(secretKey);
		
		// Get data from tweak
		const vector<uint8_t> tweakData = fromHexString(tweak);

		// Resolve performing secret key tweak add
		resolve(toHexString(secretKeyTweakAdd(contextSeed.data(), contextSeed.size(), secretKeyData.data(), secretKeyData.size(), tweakData.data(), tweakData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Public key tweak add
RCT_EXPORT_METHOD(publicKeyTweakAdd:(nonnull NSString *)publicKey
	withTweak:(nonnull NSString *)tweak
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);
		
		// Get data from tweak
		const vector<uint8_t> tweakData = fromHexString(tweak);

		// Resolve performing public key tweak add
		resolve(toHexString(publicKeyTweakAdd(contextSeed.data(), contextSeed.size(), publicKeyData.data(), publicKeyData.size(), tweakData.data(), tweakData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Secret key tweak multiply
RCT_EXPORT_METHOD(secretKeyTweakMultiply:(nonnull NSString *)secretKey
	withTweak:(nonnull NSString *)tweak
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(secretKey);
		
		// Get data from tweak
		const vector<uint8_t> tweakData = fromHexString(tweak);

		// Resolve performing secret key tweak multiply
		resolve(toHexString(secretKeyTweakMultiply(contextSeed.data(), contextSeed.size(), secretKeyData.data(), secretKeyData.size(), tweakData.data(), tweakData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Public key tweak multiply
RCT_EXPORT_METHOD(publicKeyTweakMultiply:(nonnull NSString *)publicKey
	withTweak:(nonnull NSString *)tweak
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);
		
		// Get data from tweak
		const vector<uint8_t> tweakData = fromHexString(tweak);

		// Resolve performing public key tweak multiply
		resolve(toHexString(publicKeyTweakMultiply(contextSeed.data(), contextSeed.size(), publicKeyData.data(), publicKeyData.size(), tweakData.data(), tweakData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Shared secret key from secret key and public key
RCT_EXPORT_METHOD(sharedSecretKeyFromSecretKeyAndPublicKey:(nonnull NSString *)secretKey
	withPublicKey:(nonnull NSString *)publicKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(secretKey);
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);
		
		// Resolve getting shared secret key from secret key and public key
		resolve(toHexString(sharedSecretKeyFromSecretKeyAndPublicKey(contextSeed.data(), contextSeed.size(), secretKeyData.data(), secretKeyData.size(), publicKeyData.data(), publicKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Pedersen commit
RCT_EXPORT_METHOD(pedersenCommit:(nonnull NSString *)blind
	withValue:(nonnull NSString *)value
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from blind
		const vector<uint8_t> blindData = fromHexString(blind);
		
		// Check if getting data from value failed
		const char *valueData = [value UTF8String];
		if(!valueData) {

			// Throw error
			throw runtime_error("Getting data from value failed");
		}

		// Resolve performing Pedersen commit
		resolve(toHexString(pedersenCommit(contextSeed.data(), contextSeed.size(), blindData.data(), blindData.size(), valueData)));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Pedersen commit sum
RCT_EXPORT_METHOD(pedersenCommitSum:(nonnull NSArray *)positiveCommits
	withNegativeCommits:(nonnull NSArray *)negativeCommits
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get number of positive commits
		const NSUInteger numberOfPositiveCommits = [positiveCommits count];
	
		// Initialize positive commits data and positive commits sizes
		vector<uint8_t> positiveCommitsData;
		size_t positiveCommitsSizes[numberOfPositiveCommits];
		
		// Go through all positive commits
		size_t i = 0;
		for(const NSString *commit in positiveCommits) {
		
			// Get data from commit
			const vector<uint8_t> commitData = fromHexString(commit);
			
			// Append commit data to positive commits data
			positiveCommitsData.insert(positiveCommitsData.cend(), commitData.cbegin(), commitData.cend());
			
			// Append commit data's size to positive commits sizes
			positiveCommitsSizes[i] = commitData.size();
			
			// Increment index
			++i;
		}
		
		// Get number of negative commits
		const NSUInteger numberOfNegativeCommits = [negativeCommits count];
	
		// Initialize negative commits data and negative commits sizes
		vector<uint8_t> negativeCommitsData;
		size_t negativeCommitsSizes[numberOfNegativeCommits];
		
		// Go through all negative commits
		i = 0;
		for(const NSString *commit in negativeCommits) {
		
			// Get data from commit
			const vector<uint8_t> commitData = fromHexString(commit);
			
			// Append commit data to negative commits data
			negativeCommitsData.insert(negativeCommitsData.cend(), commitData.cbegin(), commitData.cend());
			
			// Append commit data's size to negative commits sizes
			negativeCommitsSizes[i] = commitData.size();
			
			// Increment index
			++i;
		}
		
		// Resolve performing Pedersen commit sum
		resolve(toHexString(pedersenCommitSum(contextSeed.data(), contextSeed.size(), positiveCommitsData.data(), positiveCommitsSizes, numberOfPositiveCommits, negativeCommitsData.data(), negativeCommitsSizes, numberOfNegativeCommits)));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Pedersen commit to public key
RCT_EXPORT_METHOD(pedersenCommitToPublicKey:(nonnull NSString *)commit
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from commit
		const vector<uint8_t> commitData = fromHexString(commit);

		// Resolve getting public key from Pedersen commit
		resolve(toHexString(pedersenCommitToPublicKey(contextSeed.data(), contextSeed.size(), commitData.data(), commitData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Public key to Pedersen commit
RCT_EXPORT_METHOD(publicKeyToPedersenCommit:(nonnull NSString *)publicKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);

		// Resolve getting Pedersen commit from public key
		resolve(toHexString(publicKeyToPedersenCommit(contextSeed.data(), contextSeed.size(), publicKeyData.data(), publicKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Create single-signer signature
RCT_EXPORT_METHOD(createSingleSignerSignature:(nonnull NSString *)message
	withSecretKey:(nonnull NSString *)secretKey
	withSecretNonce:(NSString *)secretNonce
	withPublicKey:(nonnull NSString *)publicKey
	withPublicNonce:(NSString *)publicNonce
	withPublicNonceTotal:(NSString *)publicNonceTotal
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from message
		const vector<uint8_t> messageData = fromHexString(message);
		
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(secretKey);
		
		// Get data from secret nonce
		const vector<uint8_t> secretNonceData = secretNonce ? fromHexString(secretNonce) : vector<uint8_t>();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);
		
		// Get data from public nonce
		const vector<uint8_t> publicNonceData = publicNonce ? fromHexString(publicNonce) : vector<uint8_t>();
		
		// Get data from public nonce total
		const vector<uint8_t> publicNonceTotalData = publicNonceTotal ? fromHexString(publicNonceTotal) : vector<uint8_t>();
		
		// Check if creating random seed failed
		vector<uint8_t> seed(seedSize());
		if(SecRandomCopyBytes(kSecRandomDefault, seed.size(), seed.data()) != errSecSuccess) {
		
			// Throw error
			throw runtime_error("Creating random seed failed");
		}

		// Resolve creating single-signer signature
		resolve(toHexString(createSingleSignerSignature(contextSeed.data(), contextSeed.size(), messageData.data(), messageData.size(), secretKeyData.data(), secretKeyData.size(), secretNonce ? secretNonceData.data() : nullptr, secretNonceData.size(), publicKeyData.data(), publicKeyData.size(), publicNonce ? publicNonceData.data() : nullptr, publicNonceData.size(), publicNonceTotal ? publicNonceTotalData.data() : nullptr, publicNonceTotalData.size(), seed.data(), seed.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Add single-signer signatures
RCT_EXPORT_METHOD(addSingleSignerSignatures:(nonnull NSArray *)signatures
	withPublicNonceTotal:(nonnull NSString *)publicNonceTotal
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get number of signatures
		const NSUInteger numberOfSignatures = [signatures count];
	
		// Initialize signatures data and signatures sizes
		vector<uint8_t> signaturesData;
		size_t signaturesSizes[numberOfSignatures];
		
		// Go through all signatures
		size_t i = 0;
		for(const NSString *signature in signatures) {
		
			// Get data from signature
			const vector<uint8_t> signatureData = fromHexString(signature);
			
			// Append signature data to signatures data
			signaturesData.insert(signaturesData.cend(), signatureData.cbegin(), signatureData.cend());
			
			// Append signature data's size to signatures sizes
			signaturesSizes[i] = signatureData.size();
			
			// Increment index
			++i;
		}
		
		// Get data from public nonce total
		const vector<uint8_t> publicNonceTotalData = fromHexString(publicNonceTotal);
		
		// Resolve adding single-signer signatures
		resolve(toHexString(addSingleSignerSignatures(contextSeed.data(), contextSeed.size(), signaturesData.data(), signaturesSizes, numberOfSignatures, publicNonceTotalData.data(), publicNonceTotalData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Verify single-signer signature
RCT_EXPORT_METHOD(verifySingleSignerSignature:(nonnull NSString *)signature
	withMessage:(nonnull NSString *)message
	withPublicNonce:(NSString *)publicNonce
	withPublicKey:(nonnull NSString *)publicKey
	withPublicKeyTotal:(nonnull NSString *)publicKeyTotal
	withIsPartial:(nonnull NSNumber *)isPartial
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(signature);
		
		// Get data from message
		const vector<uint8_t> messageData = fromHexString(message);
		
		// Get data from public nonce
		const vector<uint8_t> publicNonceData = publicNonce ? fromHexString(publicNonce) : vector<uint8_t>();
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);
		
		// Get data from public key total
		const vector<uint8_t> publicKeyTotalData = fromHexString(publicKeyTotal);

		// Return if single-signer signature is verified
		resolve(toBool(verifySingleSignerSignature(contextSeed.data(), contextSeed.size(), signatureData.data(), signatureData.size(), messageData.data(), messageData.size(), publicNonce ? publicNonceData.data() : nullptr, publicNonceData.size(), publicKeyData.data(), publicKeyData.size(), publicKeyTotalData.data(), publicKeyTotalData.size(), fromBool(isPartial))));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Single-signer signature from data
RCT_EXPORT_METHOD(singleSignerSignatureFromData:(nonnull NSString *)data
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from data
		const vector<uint8_t> dataData = fromHexString(data);

		// Resolve getting single-signer signature from data
		resolve(toHexString(singleSignerSignatureFromData(contextSeed.data(), contextSeed.size(), dataData.data(), dataData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Compact single-signer signature
RCT_EXPORT_METHOD(compactSingleSignerSignature:(nonnull NSString *)signature
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(signature);

		// Resolve compacting single-signer signature
		resolve(toHexString(compactSingleSignerSignature(contextSeed.data(), contextSeed.size(), signatureData.data(), signatureData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Uncompact single-signer signature
RCT_EXPORT_METHOD(uncompactSingleSignerSignature:(nonnull NSString *)signature
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(signature);

		// Resolve uncompacting single-signer signature
		resolve(toHexString(uncompactSingleSignerSignature(contextSeed.data(), contextSeed.size(), signatureData.data(), signatureData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Combine public keys
RCT_EXPORT_METHOD(combinePublicKeys:(nonnull NSArray *)publicKeys
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get number of public keys
		const NSUInteger numberOfPublicKeys = [publicKeys count];
	
		// Initialize public keys data and public keys sizes
		vector<uint8_t> publicKeysData;
		size_t publicKeysSizes[numberOfPublicKeys];
		
		// Go through all public keys
		size_t i = 0;
		for(const NSString *publicKey in publicKeys) {
		
			// Get data from public key
			const vector<uint8_t> publicKeyData = fromHexString(publicKey);
			
			// Append public key data to public keys data
			publicKeysData.insert(publicKeysData.cend(), publicKeyData.cbegin(), publicKeyData.cend());
			
			// Append public key data's size to public keys sizes
			publicKeysSizes[i] = publicKeyData.size();
			
			// Increment index
			++i;
		}
		
		// Resolve combining public keys
		resolve(toHexString(combinePublicKeys(contextSeed.data(), contextSeed.size(), publicKeysData.data(), publicKeysSizes, numberOfPublicKeys)));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Create secret nonce
RCT_EXPORT_METHOD(createSecretNonce:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Check if creating random seed failed
		vector<uint8_t> seed(seedSize());
		if(SecRandomCopyBytes(kSecRandomDefault, seed.size(), seed.data()) != errSecSuccess) {
		
			// Throw error
			throw runtime_error("Creating random seed failed");
		}
		
		// Resolve creating secure nonce
		resolve(toHexString(createSecretNonce(contextSeed.data(), contextSeed.size(), seed.data(), seed.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Native create message hash signature
RCT_EXPORT_METHOD(createMessageHashSignature:(nonnull NSString *)messageHash
	withSecretKey:(nonnull NSString *)secretKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from message hash
		const vector<uint8_t> messageHashData = fromHexString(messageHash);
		
		// Get data from secret key
		const vector<uint8_t> secretKeyData = fromHexString(secretKey);

		// Resolve creating message hash signature
		resolve(toHexString(createMessageHashSignature(contextSeed.data(), contextSeed.size(), messageHashData.data(), messageHashData.size(), secretKeyData.data(), secretKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

// Verify message hash signature
RCT_EXPORT_METHOD(verifyMessageHashSignature:(nonnull NSString *)signature
	withMessage:(nonnull NSString *)messageHash
	withPublicKey:(nonnull NSString *)publicKey
	withResolver:(RCTPromiseResolveBlock)resolve
	withReject:(RCTPromiseRejectBlock)reject)
{

	// Try
	try {
	
		// Initialize context seed
		initializeContextSeed();
		
		// Get data from signature
		const vector<uint8_t> signatureData = fromHexString(signature);
		
		// Get data from message hash
		const vector<uint8_t> messageHashData = fromHexString(messageHash);
		
		// Get data from public key
		const vector<uint8_t> publicKeyData = fromHexString(publicKey);

		// Resolve if message hash signature is verified
		resolve(toBool(verifyMessageHashSignature(contextSeed.data(), contextSeed.size(), signatureData.data(), signatureData.size(), messageHashData.data(), messageHashData.size(), publicKeyData.data(), publicKeyData.size())));
	}

	// Catch errors
	catch(const exception &error) {

		// Initialize message
		NSString *message;

		// Try
		try {

			// Set message to error's message
			message = [NSString stringWithUTF8String:error.what()];
		}

		// Catch errors
		catch(...) {

			// Set error to nothing
			message = nullptr;
		}

		// Reject error
		reject(@"Error", message ? message : @"", nil);
	}
}

@end


// Supporting function implementation

// From hex string
vector<uint8_t> fromHexString(const NSString *hexString) {

	// Check if getting input from hex string failed
	const char *input = [hexString UTF8String];
	if(!input) {

		// Throw error
		throw runtime_error("Getting input from hex string failed");
	}

	// Get input length
	const size_t inputLength = strlen(input);

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
		result[i / HEX_CHARACTER_LENGTH] = (characterToNumber(input[i]) << BITS_IN_A_BYTE / 2) | characterToNumber(input[i + 1]);
	}

	// Return result
	return result;
}

// To hex string
const NSString *toHexString(const vector<uint8_t> &input) {

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
	const NSString *resultString = [NSString stringWithUTF8String:result.str().c_str()];
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
bool fromBool(const NSNumber *input) {

	// Return input as a bool
	return [input boolValue] == YES;
}

// To bool
const NSNumber *toBool(bool input) {

	// Check if getting input as a bool failed
	const NSNumber *result = [NSNumber numberWithBool:input ? YES : NO];
	if(!result) {

		// Throw error
		throw runtime_error("Getting input as a bool failed");
	}

	// Return result
	return result;
}

// Initialize context seed
void initializeContextSeed() {

	// Check if context seed doesn't exist
	if(contextSeed.empty()) {
	
		// Check if creating random context seed failed
		contextSeed.resize(seedSize());
		if(SecRandomCopyBytes(kSecRandomDefault, contextSeed.size(), contextSeed.data()) != errSecSuccess) {
		
			// Clear context seed
			contextSeed.clear();
			
			// Throw error
			throw runtime_error("Creating random context seed failed");
		}
	}
}
