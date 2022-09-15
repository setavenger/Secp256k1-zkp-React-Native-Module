// Package
package com.secp256k1zkpreact;


// Imports
import androidx.annotation.NonNull;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;


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
	
	// Native is valid secret key
	private static native boolean nativeIsValidSecretKey(String secretKey);
}
