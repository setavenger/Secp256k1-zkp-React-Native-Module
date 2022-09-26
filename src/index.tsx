// Imports
import { NativeModules, Platform } from "react-native";
import { Buffer } from "buffer";


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
	
	// Blind switch
	static async blindSwitch(
		blind: Buffer,
		value: string
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return performing blind switch with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.blindSwitch(blind.toString("hex"), value), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Blind sum
	static async blindSum(
		positiveBlinds: Buffer[],
		negativeBlinds: Buffer[]
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting blind sum with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.blindSum(positiveBlinds.map((positiveBlind) => {
			
				// Return positive blind as a hex string
				return positiveBlind.toString("hex");
				
			}), negativeBlinds.map((negativeBlind) => {
			
				// Return negative blind as a hex string
				return negativeBlind.toString("hex");
			})), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}

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
	
	// Is valid public key
	static async isValidPublicKey(
		publicKey: Buffer
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if public key is a valid public key with secp256k1-zkp React module
			return await NativeModules.Secp256k1ZkpReact.isValidPublicKey(publicKey.toString("hex"));
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Is valid commit
	static async isValidCommit(
		commit: Buffer
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if commit is a valid commit with secp256k1-zkp React module
			return await NativeModules.Secp256k1ZkpReact.isValidCommit(commit.toString("hex"));
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Is valid single-signer signature
	static async isValidSingleSignerSignature(
		signature: Buffer
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if signature is a valid single-signer signature with secp256k1-zkp React module
			return await NativeModules.Secp256k1ZkpReact.isValidSingleSignerSignature(signature.toString("hex"));
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Create bulletproof
	static async createBulletproof(
		blind: Buffer,
		value: string,
		nonce: Buffer,
		privateNonce: Buffer,
		extraCommit: Buffer,
		message: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting bulletproof with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.createBulletproof(blind.toString("hex"), value, nonce.toString("hex"), privateNonce.toString("hex"), extraCommit.toString("hex"), message.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Create bulletproof blindless
	static async createBulletproofBlindless(
		tauX: Buffer,
		tOne: Buffer,
		tTwo: Buffer,
		commit: Buffer,
		value: string,
		nonce: Buffer,
		extraCommit: Buffer,
		message: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting bulletproof blindless with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.createBulletproofBlindless(tauX.toString("hex"), tOne.toString("hex"), tTwo.toString("hex"), commit.toString("hex"), value, nonce.toString("hex"), extraCommit.toString("hex"), message.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Rewind bulletproof
	static async rewindBulletproof(
		proof: Buffer,
		commit: Buffer,
		nonce: Buffer
	): Promise<{[key: string]: any} | null> {
	
		// Try
		try {
	
			// Rewinding bulletproof with secp256k1-zkp React module
			const {
				Value,
				Blind,
				Message
			} = await NativeModules.Secp256k1ZkpReact.rewindBulletproof(proof.toString("hex"), commit.toString("hex"), nonce.toString("hex"));
			
			// Return bulletproof data
			return {
			
				// Value
				Value,
				
				// Blind
				Blind: Buffer.from(Blind, "hex"),
				
				// Message
				Message: Buffer.from(Message, "hex")
			};
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Verify bulletproof
	static async verifyBulletproof(
		proof: Buffer,
		commit: Buffer,
		extraCommit: Buffer
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if bulletproof is verified with secp256k1-zkp React module
			return await NativeModules.Secp256k1ZkpReact.verifyBulletproof(proof.toString("hex"), commit.toString("hex"), extraCommit.toString("hex"));
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Public key from secret key
	static async publicKeyFromSecretKey(
		secretKey: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting public key from secret key with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.publicKeyFromSecretKey(secretKey.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Public key from data
	static async publicKeyFromData(
		data: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting public key from data with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.publicKeyFromData(data.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Uncompress public key
	static async uncompressPublicKey(
		publicKey: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return uncompressing public key with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.uncompressPublicKey(publicKey.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Secret key tweak add
	static async secretKeyTweakAdd(
		secretKey: Buffer,
		tweak: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return performing secret key tweak add with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.secretKeyTweakAdd(secretKey.toString("hex"), tweak.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Public key tweak add
	static async publicKeyTweakAdd(
		publicKey: Buffer,
		tweak: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return performing public key tweak add with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.publicKeyTweakAdd(publicKey.toString("hex"), tweak.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Secret key tweak multiply
	static async secretKeyTweakMultiply(
		secretKey: Buffer,
		tweak: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return performing secret key tweak multiply with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.secretKeyTweakMultiply(secretKey.toString("hex"), tweak.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Public key tweak multiply
	static async publicKeyTweakMultiply(
		publicKey: Buffer,
		tweak: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return performing public key tweak multiply with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.publicKeyTweakMultiply(publicKey.toString("hex"), tweak.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Shared secret key from secret key and public key
	static async sharedSecretKeyFromSecretKeyAndPublicKey(
		secretKey: Buffer,
		publicKey: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting shared secret key from secret key and public key with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.sharedSecretKeyFromSecretKeyAndPublicKey(secretKey.toString("hex"), publicKey.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Pedersen commit
	static async pedersenCommit(
		blind: Buffer,
		value: string
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return performing Pedersen commit with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.pedersenCommit(blind.toString("hex"), value), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Pedersen commit sum
	static async pedersenCommitSum(
		positiveCommits: Buffer[],
		negativeCommits: Buffer[]
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return performing Pedersen commit sum with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.pedersenCommitSum(positiveCommits.map((positiveCommit) => {
			
				// Return positive commit as a hex string
				return positiveCommit.toString("hex");
				
			}), negativeCommits.map((negativeCommit) => {
			
				// Return negative commit as a hex string
				return negativeCommit.toString("hex");
			})), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Pedersen commit to public key
	static async pedersenCommitToPublicKey(
		commit: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting public key from Pedersen commit with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.pedersenCommitToPublicKey(commit.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Public key to Pedersen commit
	static async publicKeyToPedersenCommit(
		publicKey: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting Pedersen commit from public key with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.publicKeyToPedersenCommit(publicKey.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Create single-signer signature
	static async createSingleSignerSignature(
		message: Buffer,
		secretKey: Buffer,
		secretNonce: Buffer | null,
		publicKey: Buffer,
		publicNonce: Buffer | null,
		publicNonceTotal: Buffer | null
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting single-signer signature with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.createSingleSignerSignature(message.toString("hex"), secretKey.toString("hex"), (secretNonce !== null) ? secretNonce.toString("hex") : null, publicKey.toString("hex"), (publicNonce !== null) ? publicNonce.toString("hex") : null, (publicNonceTotal !== null) ? publicNonceTotal.toString("hex") : null), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Pedersen commit sum
	static async addSingleSignerSignatures(
		signatures: Buffer[],
		publicNonceTotal: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return adding single-signer signatures with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.addSingleSignerSignatures(signatures.map((signature) => {
			
				// Return signature as a hex string
				return signature.toString("hex");
				
			}), publicNonceTotal.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Verify single-signer signature
	static async verifySingleSignerSignature(
		signature: Buffer,
		message: Buffer,
		publicNonce: Buffer | null,
		publicKey: Buffer,
		publicKeyTotal: Buffer,
		isPartial: boolean
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if single-signer signature is verified with secp256k1-zkp React module
			return await NativeModules.Secp256k1ZkpReact.verifySingleSignerSignature(signature.toString("hex"), message.toString("hex"), (publicNonce !== null) ? publicNonce.toString("hex") : null, publicKey.toString("hex"), publicKeyTotal.toString("hex"), isPartial);
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Single-signer signature from data
	static async singleSignerSignatureFromData(
		data: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting single-signer signature from data with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.singleSignerSignatureFromData(data.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Compact single-signer signature
	static async compactSingleSignerSignature(
		signature: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return compacting single-signer signature with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.compactSingleSignerSignature(signature.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Uncompact single-signer signature
	static async uncompactSingleSignerSignature(
		signature: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return uncompacting single-signer signature with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.uncompactSingleSignerSignature(signature.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Combine public keys
	static async combinePublicKeys(
		publicKeys: Buffer[]
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return combining public keys with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.combinePublicKeys(publicKeys.map((publicKey) => {
			
				// Return public key as a hex string
				return publicKey.toString("hex");
				
			})), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Create secret nonce
	static async createSecretNonce(): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting secret nonce with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.createSecretNonce(), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Create message hash signature
	static async createMessageHashSignature(
		messageHash: Buffer,
		secretKey: Buffer
	): Promise<Buffer | null> {
	
		// Try
		try {
	
			// Return getting message hash signature with secp256k1-zkp React module
			return Buffer.from(await NativeModules.Secp256k1ZkpReact.createMessageHashSignature(messageHash.toString("hex"), secretKey.toString("hex")), "hex");
		}
		
		// Catch errors
		catch(
			error: any
		) {
		
			// Return operation failed
			return Secp256k1Zkp.OPERATION_FAILED;
		}
	}
	
	// Verify message hash signature
	static async verifyMessageHashSignature(
		signature: Buffer,
		messageHash: Buffer,
		publicKey: Buffer
	): Promise<boolean | null> {
	
		// Try
		try {
	
			// Return if message hash signature is verified with secp256k1-zkp React module
			return await NativeModules.Secp256k1ZkpReact.verifyMessageHashSignature(signature.toString("hex"), messageHash.toString("hex"), publicKey.toString("hex"));
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
