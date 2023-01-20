// Package
package com.secp256k1zkpreact;


// Imports
import androidx.annotation.NonNull;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import java.security.SecureRandom;


// Classes

// Secp256k1-zkp React module class
@ReactModule(name = Secp256k1ZkpReactModule.NAME)
public class Secp256k1ZkpReactModule extends ReactContextBaseJavaModule {

	// Name
	public static final String NAME = "Secp256k1ZkpReact";
	
	// Static
	static {
	
		// Try
		try {
		
			// Load library
			System.loadLibrary("Secp256k1ZkpReact");
		}
		
		// Catch errors
		catch(Exception error) {
		
		}
	}

	// Constructor
	public Secp256k1ZkpReactModule(ReactApplicationContext reactContext) {
	
		// Delegate constructor
		super(reactContext);
	}

	// Get name
	@Override
	@NonNull
	public String getName() {
	
		// Return name
		return NAME;
	}
	
	// Blind switch
	@ReactMethod
	public void blindSwitch(String blind, String value, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native blind switch
			promise.resolve(nativeBlindSwitch(toHexString(contextSeed), blind, value));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Blind sum
	@ReactMethod
	public void blindSum(ReadableArray positiveBlinds, ReadableArray negativeBlinds, Promise promise) {
	
		// Try
		try {
		
			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native blind sum
			promise.resolve(nativeBlindSum(toHexString(contextSeed), fromReadableArray(positiveBlinds), fromReadableArray(negativeBlinds)));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Is valid secret key
	@ReactMethod
	public void isValidSecretKey(String secretKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native is valid secret key
			promise.resolve(nativeIsValidSecretKey(toHexString(contextSeed), secretKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Is valid public key
	@ReactMethod
	public void isValidPublicKey(String publicKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native is valid public key
			promise.resolve(nativeIsValidPublicKey(toHexString(contextSeed), publicKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Is valid commit
	@ReactMethod
	public void isValidCommit(String commit, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native is valid commit
			promise.resolve(nativeIsValidCommit(toHexString(contextSeed), commit));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Is valid single-signer signature
	@ReactMethod
	public void isValidSingleSignerSignature(String signature, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native is single-signer signature
			promise.resolve(nativeIsValidSingleSignerSignature(toHexString(contextSeed), signature));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Create bulletproof
	@ReactMethod
	public void createBulletproof(String blind, String value, String nonce, String privateNonce, String extraCommit, String message, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native create bulletproof
			promise.resolve(nativeCreateBulletproof(toHexString(contextSeed), blind, value, nonce, privateNonce, extraCommit, message));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Create bulletproof blindless
	@ReactMethod
	public void createBulletproofBlindless(String tauX, String tOne, String tTwo, String commit, String value, String nonce, String extraCommit, String message, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native create bulletproof blindless
			promise.resolve(nativeCreateBulletproofBlindless(toHexString(contextSeed), tauX, tOne, tTwo, commit, value, nonce, extraCommit, message));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Rewind bulletproof
	@ReactMethod
	public void rewindBulletproof(String proof, String commit, String nonce, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Get bulletproof data from native rewind bulletproof
			String[] bulletproofData = nativeRewindBulletproof(toHexString(contextSeed), proof, commit, nonce);
			
			// Initialize result
			WritableMap result = Arguments.createMap();
			
			// Add bulletproof data to result
			result.putString("Value", bulletproofData[0]);
			result.putString("Blind", bulletproofData[1]);
			result.putString("Message", bulletproofData[2]);
			
			// Resolve promise to result
			promise.resolve(result);
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Verify bulletproof
	@ReactMethod
	public void verifyBulletproof(String proof, String commit, String extraCommit, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native verify bulletproof
			promise.resolve(nativeVerifyBulletproof(toHexString(contextSeed), proof, commit, extraCommit));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Public key from secret key
	@ReactMethod
	public void publicKeyFromSecretKey(String secretKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native public key from secret key
			promise.resolve(nativePublicKeyFromSecretKey(toHexString(contextSeed), secretKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Public key from data
	@ReactMethod
	public void publicKeyFromData(String data, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native public key from data
			promise.resolve(nativePublicKeyFromData(toHexString(contextSeed), data));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Uncompress public key
	@ReactMethod
	public void uncompressPublicKey(String publicKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native uncompress public key
			promise.resolve(nativeUncompressPublicKey(toHexString(contextSeed), publicKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Secret key tweak add
	@ReactMethod
	public void secretKeyTweakAdd(String secretKey, String tweak, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native secret key tweak add
			promise.resolve(nativeSecretKeyTweakAdd(toHexString(contextSeed), secretKey, tweak));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Public key tweak add
	@ReactMethod
	public void publicKeyTweakAdd(String publicKey, String tweak, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native public key tweak add
			promise.resolve(nativePublicKeyTweakAdd(toHexString(contextSeed), publicKey, tweak));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Secret key tweak multiply
	@ReactMethod
	public void secretKeyTweakMultiply(String secretKey, String tweak, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native secret key tweak multiply
			promise.resolve(nativeSecretKeyTweakMultiply(toHexString(contextSeed), secretKey, tweak));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Public key tweak multiply
	@ReactMethod
	public void publicKeyTweakMultiply(String publicKey, String tweak, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native public key tweak multiply
			promise.resolve(nativePublicKeyTweakMultiply(toHexString(contextSeed), publicKey, tweak));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Shared secret key from secret key and public key
	@ReactMethod
	public void sharedSecretKeyFromSecretKeyAndPublicKey(String secretKey, String publicKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native shared secret key from secret key and public key
			promise.resolve(nativeSharedSecretKeyFromSecretKeyAndPublicKey(toHexString(contextSeed), secretKey, publicKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Pedersen commit
	@ReactMethod
	public void pedersenCommit(String blind, String value, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native Pedersen commit
			promise.resolve(nativePedersenCommit(toHexString(contextSeed), blind, value));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Pedersen commit sum
	@ReactMethod
	public void pedersenCommitSum(ReadableArray positiveCommits, ReadableArray negativeCommits, Promise promise) {
	
		// Try
		try {
		
			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native Pedersen commit sum
			promise.resolve(nativePedersenCommitSum(toHexString(contextSeed), fromReadableArray(positiveCommits), fromReadableArray(negativeCommits)));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Pedersen commit to public key
	@ReactMethod
	public void pedersenCommitToPublicKey(String commit, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native Pedersen commit to public key
			promise.resolve(nativePedersenCommitToPublicKey(toHexString(contextSeed), commit));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Public key to Pedersen commit
	@ReactMethod
	public void publicKeyToPedersenCommit(String publicKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native public key to Pedersen commit
			promise.resolve(nativePublicKeyToPedersenCommit(toHexString(contextSeed), publicKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Create single-signer signature
	@ReactMethod
	public void createSingleSignerSignature(String message, String secretKey, String secretNonce, String publicKey, String publicNonce, String publicNonceTotal, Promise promise) {

		// Try
		try {
		
			// Initialize context seed
			initializeContextSeed();
			
			// Create random seed
			SecureRandom random = new SecureRandom();
			byte[] seed = new byte[nativeSeedSize()];
			random.nextBytes(seed);

			// Resolve promise to native create single-signer signature
			promise.resolve(nativeCreateSingleSignerSignature(toHexString(contextSeed), message, secretKey, secretNonce, publicKey, publicNonce, publicNonceTotal, toHexString(seed)));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Add single-signer signatures
	@ReactMethod
	public void addSingleSignerSignatures(ReadableArray signatures, String publicNonceTotal, Promise promise) {
	
		// Try
		try {
		
			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native add single-signer signatures
			promise.resolve(nativeAddSingleSignerSignatures(toHexString(contextSeed), fromReadableArray(signatures), publicNonceTotal));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Verify single-signer signature
	@ReactMethod
	public void verifySingleSignerSignature(String signature, String message, String publicNonce, String publicKey, String publicKeyTotal, boolean isPartial, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native verify single-signer signature
			promise.resolve(nativeVerifySingleSignerSignature(toHexString(contextSeed), signature, message, publicNonce, publicKey, publicKeyTotal, isPartial));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Single-signer signature from data
	@ReactMethod
	public void singleSignerSignatureFromData(String data, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native single-signer signature from data
			promise.resolve(nativeSingleSignerSignatureFromData(toHexString(contextSeed), data));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Compact single-signer signature
	@ReactMethod
	public void compactSingleSignerSignature(String signature, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native compact single-signer signature
			promise.resolve(nativeCompactSingleSignerSignature(toHexString(contextSeed), signature));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Uncompact single-signer signature
	@ReactMethod
	public void uncompactSingleSignerSignature(String signature, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native uncompact single-signer signature
			promise.resolve(nativeUncompactSingleSignerSignature(toHexString(contextSeed), signature));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Combine public keys
	@ReactMethod
	public void combinePublicKeys(ReadableArray publicKeys, Promise promise) {
	
		// Try
		try {
		
			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native combine public keys
			promise.resolve(nativeCombinePublicKeys(toHexString(contextSeed), fromReadableArray(publicKeys)));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Create secret nonce
	@ReactMethod
	public void createSecretNonce(Promise promise) {

		// Try
		try {
		
			// Initialize context seed
			initializeContextSeed();
			
			// Create random seed
			SecureRandom random = new SecureRandom();
			byte[] seed = new byte[nativeSeedSize()];
			random.nextBytes(seed);

			// Resolve promise to native create secret nonce
			promise.resolve(nativeCreateSecretNonce(toHexString(contextSeed), toHexString(seed)));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Create message hash signature
	@ReactMethod
	public void createMessageHashSignature(String messageHash, String secretKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native create message hash signature
			promise.resolve(nativeCreateMessageHashSignature(toHexString(contextSeed), messageHash, secretKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Verify message hash signature
	@ReactMethod
	public void verifyMessageHashSignature(String signature, String messageHash, String publicKey, Promise promise) {

		// Try
		try {

			// Initialize context seed
			initializeContextSeed();
			
			// Resolve promise to native verify message hash signature
			promise.resolve(nativeVerifyMessageHashSignature(toHexString(contextSeed), signature, messageHash, publicKey));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Hex character length
	private static final int HEX_CHARACTER_LENGTH = 2;
	
	// Context seed
	private static byte[] contextSeed = null;
	
	// Native blind switch
	private static native String nativeBlindSwitch(String contextSeed, String blind, String value);
	
	// Native blind sum
	private static native String nativeBlindSum(String contextSeed, String[] positiveBlinds, String[] negativeBlinds);
	
	// Native is valid secret key
	private static native boolean nativeIsValidSecretKey(String contextSeed, String secretKey);
	
	// Native is valid public key
	private static native boolean nativeIsValidPublicKey(String contextSeed, String publicKey);
	
	// Native is valid commit
	private static native boolean nativeIsValidCommit(String contextSeed, String commit);
	
	// Native is valid single-signer signature
	private static native boolean nativeIsValidSingleSignerSignature(String contextSeed, String signature);
	
	// Native create bulletproof
	private static native String nativeCreateBulletproof(String contextSeed, String blind, String value, String nonce, String privateNonce, String extraCommit, String message);
	
	// Native create bulletproof blindless
	private static native String nativeCreateBulletproofBlindless(String contextSeed, String tauX, String tOne, String tTwo, String commit, String value, String nonce, String extraCommit, String message);
	
	// Native rewind bulletproof
	private static native String[] nativeRewindBulletproof(String contextSeed, String proof, String commit, String nonce);
	
	// Native verify bulletproof
	private static native boolean nativeVerifyBulletproof(String contextSeed, String proof, String commit, String extraCommit);
	
	// Native public key from secret key
	private static native String nativePublicKeyFromSecretKey(String contextSeed, String secretKey);
	
	// Native public key from data
	private static native String nativePublicKeyFromData(String contextSeed, String data);
	
	// Native uncompress public key
	private static native String nativeUncompressPublicKey(String contextSeed, String publicKey);
	
	// Native secret key tweak add
	private static native String nativeSecretKeyTweakAdd(String contextSeed, String secretKey, String tweak);
	
	// Native public key tweak add
	private static native String nativePublicKeyTweakAdd(String contextSeed, String publicKey, String tweak);
	
	// Native secret key tweak multiply
	private static native String nativeSecretKeyTweakMultiply(String contextSeed, String secretKey, String tweak);
	
	// Native public key tweak multiply
	private static native String nativePublicKeyTweakMultiply(String contextSeed, String publicKey, String tweak);
	
	// Native shared secret key from secret key and public key
	private static native String nativeSharedSecretKeyFromSecretKeyAndPublicKey(String contextSeed, String secretKey, String publicKey);
	
	// Native Pedersen commit
	private static native String nativePedersenCommit(String contextSeed, String blind, String value);
	
	// Native Pedersen commit sum
	private static native String nativePedersenCommitSum(String contextSeed, String[] positiveCommits, String[] negativeCommits);
	
	// Native Pedersen commit to public key
	private static native String nativePedersenCommitToPublicKey(String contextSeed, String commit);
	
	// Native public key to Pedersen commit
	private static native String nativePublicKeyToPedersenCommit(String contextSeed, String publicKey);
	
	// Native create single-signer signature
	private static native String nativeCreateSingleSignerSignature(String contextSeed, String message, String secretKey, String secretNonce, String publicKey, String publicNonce, String publicNonceTotal, String seed);
	
	// Native add single-signer signatures
	private static native String nativeAddSingleSignerSignatures(String contextSeed, String[] signatures, String publicNonceTotal);
	
	// Native verify single-signer signature
	private static native boolean nativeVerifySingleSignerSignature(String contextSeed, String signature, String message, String publicNonce, String publicKey, String publicKeyTotal, boolean isPartial);
	
	// Native single-signer signature from data
	private static native String nativeSingleSignerSignatureFromData(String contextSeed, String data);
	
	// Native compact single-signer signature
	private static native String nativeCompactSingleSignerSignature(String contextSeed, String signature);
	
	// Native uncompact single-signer signature
	private static native String nativeUncompactSingleSignerSignature(String contextSeed, String signature);
	
	// Native combine public keys
	private static native String nativeCombinePublicKeys(String contextSeed, String[] publicKeys);
	
	// Native create secret nonce
	private static native String nativeCreateSecretNonce(String contextSeed, String seed);
	
	// Native create message hash signature
	private static native String nativeCreateMessageHashSignature(String contextSeed, String messageHash, String secretKey);
	
	// Native verify message hash signature
	private static native boolean nativeVerifyMessageHashSignature(String contextSeed, String signature, String messageHash, String publicKey);
	
	// Native seed size
	private static native int nativeSeedSize();
	
	// From readable array
	private static String[] fromReadableArray(ReadableArray readableArray) throws Exception {
	
		// Initialize result
		String[] result = new String[readableArray.size()];
		
		// Go through all values in the readable array
		for(int i = 0; i < readableArray.size(); ++i) {
		
			// Check if value isn't a string
			if(readableArray.getType(i) != ReadableType.String) {
			
				// Throw error
				throw new Exception("Readable array value isn't a string");
			}
		
			// Set value in the result to the value
			result[i] = readableArray.getString(i);
		}
		
		// Return result
		return result;
	}
	
	// To hex string
	private static String toHexString(byte[] input) {
	
		// Create result
		StringBuilder result = new StringBuilder(input.length * HEX_CHARACTER_LENGTH);
		
		// Go through all bytes in the input
		for(byte inputByte : input) {
		
			// Append byte to result
			result.append(String.format("%02x", inputByte));
		}
		
		// Return result as a string
		return result.toString();
	}
	
	// Initialize context seed
	private static void initializeContextSeed() {
	
		// Check if context seed doesn't exist
		if(contextSeed == null) {
		
			// Try
			try {
		
				// Create random context seed
				SecureRandom random = new SecureRandom();
				contextSeed = new byte[nativeSeedSize()];
				random.nextBytes(contextSeed);
			}
			
			// Catch errors
			catch(Exception error) {

				// Clear context seed
				contextSeed = null;
				
				// Throw error
				throw error;
			}
		}
	}
}
