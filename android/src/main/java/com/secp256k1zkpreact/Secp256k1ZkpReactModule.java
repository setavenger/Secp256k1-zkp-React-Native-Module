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
	
	// Blind sum
	@ReactMethod
	public void blindSum(ReadableArray positiveBlinds, ReadableArray negativeBlinds, Promise promise) {
	
		// Try
		try {
		
			// Resolve promise to native blind sum
			promise.resolve(nativeBlindSum(fromReadableArray(positiveBlinds), fromReadableArray(negativeBlinds)));
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

			// Resolve promise to native is valid secret key
			promise.resolve(nativeIsValidSecretKey(secretKey));
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

			// Resolve promise to native is valid public key
			promise.resolve(nativeIsValidPublicKey(publicKey));
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

			// Resolve promise to native is valid commit
			promise.resolve(nativeIsValidCommit(commit));
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

			// Resolve promise to native is single-signer signature
			promise.resolve(nativeIsValidSingleSignerSignature(signature));
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

			// Resolve promise to native create bulletproof blindless
			promise.resolve(nativeCreateBulletproofBlindless(tauX, tOne, tTwo, commit, value, nonce, extraCommit, message));
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

			// Get bulletproof data from native rewind bulletproof
			String[] bulletproofData = nativeRewindBulletproof(proof, commit, nonce);
			
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

			// Resolve promise to native verify bulletproof
			promise.resolve(nativeVerifyBulletproof(proof, commit, extraCommit));
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

			// Resolve promise to native public key from data
			promise.resolve(nativePublicKeyFromData(data));
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

			// Resolve promise to native Pedersen commit
			promise.resolve(nativePedersenCommit(blind, value));
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
		
			// Resolve promise to native Pedersen commit sum
			promise.resolve(nativePedersenCommitSum(fromReadableArray(positiveCommits), fromReadableArray(negativeCommits)));
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

			// Resolve promise to native Pedersen commit to public key
			promise.resolve(nativePedersenCommitToPublicKey(commit));
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

			// Resolve promise to native public key to Pedersen commit
			promise.resolve(nativePublicKeyToPedersenCommit(publicKey));
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
		
			// Resolve promise to native add single-signer signatures
			promise.resolve(nativeAddSingleSignerSignatures(fromReadableArray(signatures), publicNonceTotal));
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

			// Resolve promise to native verify single-signer signature
			promise.resolve(nativeVerifySingleSignerSignature(signature, message, publicNonce, publicKey, publicKeyTotal, isPartial));
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

			// Resolve promise to native single-signer signature from data
			promise.resolve(nativeSingleSignerSignatureFromData(data));
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

			// Resolve promise to native compact single-signer signature
			promise.resolve(nativeCompactSingleSignerSignature(signature));
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

			// Resolve promise to native uncompact single-signer signature
			promise.resolve(nativeUncompactSingleSignerSignature(signature));
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
		
			// Resolve promise to native combine public keys
			promise.resolve(nativeCombinePublicKeys(fromReadableArray(publicKeys)));
		}

		// Catch errors
		catch(Exception error) {

			// Reject promise
			promise.reject("Error", error);
		}
	}
	
	// Native blind sum
	private static native String nativeBlindSum(String[] positiveBlinds, String[] negativeBlinds);
	
	// Native is valid secret key
	private static native boolean nativeIsValidSecretKey(String secretKey);
	
	// Native is valid public key
	private static native boolean nativeIsValidPublicKey(String publicKey);
	
	// Native is valid commit
	private static native boolean nativeIsValidCommit(String commit);
	
	// Native is valid single-signer signature
	private static native boolean nativeIsValidSingleSignerSignature(String signature);
	
	// Native create bulletproof blindless
	private static native String nativeCreateBulletproofBlindless(String tauX, String tOne, String tTwo, String commit, String value, String nonce, String extraCommit, String message);
	
	// Native rewind bulletproof
	private static native String[] nativeRewindBulletproof(String proof, String commit, String nonce);
	
	// Native verify bulletproof
	private static native boolean nativeVerifyBulletproof(String proof, String commit, String extraCommit);
	
	// Native public key from data
	private static native String nativePublicKeyFromData(String data);
	
	// Native Pedersen commit
	private static native String nativePedersenCommit(String blind, String value);
	
	// Native Pedersen commit sum
	private static native String nativePedersenCommitSum(String[] positiveCommits, String[] negativeCommits);
	
	// Native Pedersen commit to public key
	private static native String nativePedersenCommitToPublicKey(String commit);
	
	// Native public key to Pedersen commit
	private static native String nativePublicKeyToPedersenCommit(String publicKey);
	
	// Native add single-signer signatures
	private static native String nativeAddSingleSignerSignatures(String[] signatures, String publicNonceTotal);
	
	// Native verify single-signer signature
	private static native boolean nativeVerifySingleSignerSignature(String signature, String message, String publicNonce, String publicKey, String publicKeyTotal, boolean isPartial);
	
	// Native single-signer signature from data
	private static native String nativeSingleSignerSignatureFromData(String data);
	
	// Native compact single-signer signature
	private static native String nativeCompactSingleSignerSignature(String signature);
	
	// Native uncompact single-signer signature
	private static native String nativeUncompactSingleSignerSignature(String signature);
	
	// Native combine public keys
	private static native String nativeCombinePublicKeys(String[] publicKeys);
	
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
}
