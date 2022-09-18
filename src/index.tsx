// Imports
import { NativeModules, Platform } from "react-native";
//import { Buffer } from "buffer";


// Check if secp256k1-zkp React module doesn't exist
if(!NativeModules.Secp256k1ZkpReact) {

	// Throw error
	throw new Error("The package '@nicolasflamel/secp256k1-zkp-react' doesn't seem to be linked. Make sure: \n\n" + Platform.select({
		ios: "- You have run 'pod install'\n",
		default: ""
	}) + "- You rebuilt the app after installing the package\n- You are not using Expo managed workflow\n");
}


// Classes

// Secp256k1-zkp class
export default class Secp256k1Zkp {

	// Operation failed
	public static readonly OPERATION_FAILED = null;
	
	// No secret nonce
	public static readonly NO_SECRET_NONCE = null;
	
	// No public nonce
	public static readonly NO_PUBLIC_NONCE = null;
	
	// No public nonce total
	public static readonly NO_PUBLIC_NONCE_TOTAL = null;
	
	// blindSum

	// Is valid secret key
	static async isValidSecretKey(
		secretKey: Buffer
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if secret key is a valid secret key with secp256k1-zkp React module
			return await NativeModules.Secp256k1ZkpReact.isValidSecretKey(secretKey.toString("hex"));
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	/*isValidSecretKey
	isValidPublicKey
	isValidCommit
	isValidSingleSignerSignature
	*createBulletproofBlindless
	*rewindBulletproof
	*verifyBulletproof
	publicKeyFromData
	pedersenCommit
	pedersenCommitSum
	pedersenCommitToPublicKey
	publicKeyToPedersenCommit
	addSingleSignerSignatures
	verifySingleSignerSignature
	singleSignerSignatureFromData
	compactSingleSignerSignature
	uncompactSingleSignerSignature
	combinePublicKeys*/
}
