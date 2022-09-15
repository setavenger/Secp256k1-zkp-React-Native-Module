// Imports
import { NativeModules, Platform } from "react-native";
//import { Buffer } from "buffer";


// Constants

// Linking error
const LINKING_ERROR = "The package '@nicolasflamel/secp256k1-zkp-react' doesn't seem to be linked. Make sure: \n\n" + Platform.select({ ios: "- You have run 'pod install'\n", default: "" }) + "- You rebuilt the app after installing the package\n- You are not using Expo managed workflow\n";

// Secp256k1-zkp React
const Secp256k1ZkpReact = NativeModules.Secp256k1ZkpReact ? NativeModules.Secp256k1ZkpReact : new Proxy({}, {
	get() {
		throw new Error(LINKING_ERROR);
	}
});


// Classes

// Secp256k1-zkp class
export default class Secp256k1Zkp {

	// Operation failed
	public static readonly OPERATION_FAILED = null;

	// Is valid secret key
	static async isValidSecretKey(
		secretKey: Buffer
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if secret key is a valid secret key
			return await Secp256k1ZkpReact.isValidSecretKey(secretKey.toString("hex"));
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
}
