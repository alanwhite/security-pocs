package xyz.arwhite.ecdh;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/***
 * Utility class to encrypt/decrypt data using symmetric key produced as a result of exchanging
 * public keys with another instance. 
 * 
 * No 3rd party dependencies. This makes it lightweight but not battle hardened, link google tink.
 * 
 * So DO NOT USE IN PRODUCTION. This is a learning tool for me. E.G. no private key rotation method yet.
 * 
 * Props to https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/
 * And then also to every stackoverflow answer that talks about ciphers and encryption.
 * 
 * @author Alan R. White
 *
 */
public class ECDHPeer {

	// NIST recommends AES-GCM (TODO: find reference)
	// private static final String algorithm = "AES/CBC/PKCS5Padding";
	private static final String algorithm = "AES/GCM/NoPadding";

	private KeyPair myKeyPair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private PublicKey peerPublicKey;
	private SecretKey symmetricKey;

	public ECDHPeer() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		myKeyPair = keyPairGen.generateKeyPair();
		publicKey = myKeyPair.getPublic();
		privateKey = myKeyPair.getPrivate();
	}

	/**
	 * Provides the public key of the peer with which we wish to generate an identical symmetric key.
	 * The symmetric key is produced as a result of combining this public key with the internal provate
	 * key generated in the constructor, and then applying a SHA-256 hash.
	 * 
	 * @param peerPublicKey
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 */
	public void setPeerPublicKey(PublicKey peerPublicKey) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

		if ( !(peerPublicKey instanceof ECPublicKey) 
				|| !this.validatePublicKey((ECPublicKey) peerPublicKey) ) 
			throw new IllegalArgumentException("Peer Public Key is not a valid EC Public Key");

		this.peerPublicKey = peerPublicKey;		
		this.symmetricKey = this.generateSymmetricKey(myKeyPair, peerPublicKey);
	}

	/**
	 * Obtain our public key
	 * 
	 * @return the public key generated in the constructor
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Encrypts the provided string using the symmetric key generated when a peer public key was provided
	 * 
	 * @param input the String to be encrypted
	 * @return the encrypted String
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String encrypt(String input) throws NoSuchPaddingException, NoSuchAlgorithmException,
	InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {

		// https://stackoverflow.com/questions/67028762/why-aes-256-with-gcm-adds-16-bytes-to-the-ciphertext-size
		// Recommends 12 byte IV
		byte[] ivRaw = new byte[12];
		new SecureRandom().nextBytes(ivRaw);
		var iv = new IvParameterSpec(ivRaw);
		var iv64 = Base64.getEncoder().encodeToString(iv.getIV());

		var gcm = new GCMParameterSpec(128, iv.getIV());

		Cipher cipher = Cipher.getInstance(ECDHPeer.algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, gcm);
		byte[] cipherText = cipher.doFinal(input.getBytes());

		var cipherText64 = Base64.getEncoder().encodeToString(cipherText);

		return iv64 + "." + cipherText64;
	}

	/**
	 * Decrypts an encrypted String created by the encrypt method, using the symmetric key generated when
	 * a peer public key was provided
	 * 
	 * @param cipherText the encrypted String to be decrypted
	 * @return the plain text String decrypted from the cipherText
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String decrypt(String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException,
	InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {

		var blocks = cipherText.split("\\.");
		if ( blocks.length != 2 )
			throw new IllegalArgumentException("payload is not encrypted by ECDHPeer");

		var iv64 = blocks[0];
		var cipherText64 = blocks[1];

		var iv = new IvParameterSpec(Base64.getDecoder().decode(iv64));

		var gcm = new GCMParameterSpec(128, iv.getIV());

		Cipher cipher = Cipher.getInstance(ECDHPeer.algorithm);
		cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, gcm);
		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText64));
		return new String(plainText);
	}

	/**
	 * https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
	 * 
	 * Which tbh I'm still trying to truly understand, rather than generally!
	 * 
	 * @param publicKey
	 * @return true if it passes standard EC checks, else false
	 */

	private boolean validatePublicKey(ECPublicKey publicKey) {
		// Step 1: Verify public key is not point at infinity. 
		if (ECPoint.POINT_INFINITY.equals(publicKey.getW())) {
			return false;
		}

		return true;

		/*

		final BigInteger x = publicKey.getW().getAffineX();
		final BigInteger y = publicKey.getW().getAffineY();
		final BigInteger p = ((ECFieldFp) curveParams.getField()).getP();

		// Step 2: Verify x and y are in range [0,p-1]
		if (x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(p) >= 0
				|| y.compareTo(BigInteger.ZERO) < 0 || y.compareTo(p) >= 0) {
			return false;
		}

		final BigInteger a = curveParams.getA();
		final BigInteger b = curveParams.getB();

		// Step 3: Verify that y^2 == x^3 + ax + b (mod p)
		final BigInteger ySquared = y.modPow(TWO, p);
		final BigInteger xCubedPlusAXPlusB = x.modPow(THREE, p).add(a.multiply(x)).add(b).mod(p);
		if (!ySquared.equals(xCubedPlusAXPlusB)) {
			return false;
		}

		 */
	}


	/**
	 * Produces a signature of the provided String using the private key generated in the constructor
	 * 
	 * @param anyText the text from which a signature will be generated
	 * @return the signature of the provided String
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public String sign(String anyText) 
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature privateSignature = Signature.getInstance("SHA256withECDSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(anyText.getBytes());

		byte[] signature = privateSignature.sign();

		return Base64.getEncoder().encodeToString(signature);
	}

	/**
	 * Verifies the signature of the provided String using the public key generated in our constructor
	 * 
	 * @param anyText String containing the data on which the signature was based
	 * @param signature String containing the alleged signature of the provided String 
	 * @return true if anyText was signed by our private key, else false
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public boolean verify(String anyText, String signature) 
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature publicSignature = Signature.getInstance("SHA256withECDSA");
		publicSignature.initVerify(publicKey);
		publicSignature.update(anyText.getBytes());

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		return publicSignature.verify(signatureBytes);
	}

	/**
	 * Verifies the signature of the provided String using the public key provided in setPeerPublicKey
	 * 
	 * @param plainText String containing the data on which the signature was based
	 * @param signature String containing the alleged signature of the provided String created using 
	 * the private key associated with the peer public key
	 * @return true if anyText was signed by the peer private key, else false
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public boolean verifyPeer(String plainText, String signature) 
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature publicSignature = Signature.getInstance("SHA256withECDSA");
		publicSignature.initVerify(peerPublicKey);
		publicSignature.update(plainText.getBytes());

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		return publicSignature.verify(signatureBytes);
	}

	/*
	 * Proof of Possession:
	 * 
	 * The 2 methods below illustrate how one party that has obtained the public key
	 * issued by another party can validate that the issuer of that public key does
	 * possess the private key that corresponds to it.
	 * 
	 * Again, not for production use on it's own, the public key exchange should have
	 * some form of trustable provenance involved, e.g. the public key was retrieved 
	 * from a certificate that has a verifiable chain of trust. Another mechanism could
	 * be that the public key was obtained through some other authenticated exchange, e.g.
	 * a human is attesting to it's provenance by passing it to the validating party via
	 * personal authentication to a website.
	 * 
	 * The party that has obtained the public key of the other is said to challenge the
	 * other party to prove they hold the private key. This is achieved, at a high level,
	 * by challenger encrypting a nonce in a manner that uses the public key it holds,
	 * then transmitting that encrypted nonce to the other party. If the other party 
	 * can prove to the challenger that they can successfully decrypt that nonce, then
	 * they have proved they possess the private key that corresponds to the public key.
	 * 
	 * Various protections need to take place in this exchange, e.g. proving the messages
	 * haven't been tampered with in transit by any in-the-middle interception attacks.
	 */
	
	/**
	 * Structure for standardising the format of the data used in the challenge and response
	 * operations between the two parties.
	 */
	public record PoP(
			String encryptedNonce, // hex string of byte[] 
			PublicKey publicKey, // should really make this a string with the hex public key bytes in it
			String iv, // hex string of byte[]
			String hmac, // hex string of byte[]
			String kdf, // text 
			String algorithm // text
			) {}
	
	private void printPoP(PoP pop) {
		System.out.println("Nonce: "+pop.encryptedNonce());
		System.out.println("Public Key: "+pop.publicKey());
		System.out.println("IV Hex: "+pop.iv());
		System.out.println("HMAC Hex: "+pop.hmac());
		System.out.println("Key Def Func: "+pop.kdf());
		System.out.println("Enc Algorithm: "+pop.algorithm());
	}
	
	/**
	 * Using the public key from the other peer, populates a proof of possession object and
	 * challenges the peer to prove they have the private key that corresponds.
	 * 
	 * @param other the peer whose possession of the private key is being determined
	 * @return true if the peer has proved it holds the private key otherwise false
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeySpecException
	 */
	public boolean performPoPChallenge(ECDHPeer other) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, 
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
			BadPaddingException, InvalidKeySpecException {

		System.out.println("\nPerforming PoP Challenge ....");
		var hex = HexFormat.of();
		
		// get 256 bytes of random 
		byte[] rawNonce = new byte[256]; 
		SecureRandom.getInstanceStrong().nextBytes(rawNonce);
		var nonce64 = Base64.getEncoder().encode(rawNonce); // would have thought base64 encoding after enc was more appropriate
		
		// create ephemeral keypair
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		KeyPair challengeKeyPair = keyPairGen.generateKeyPair();

		// Perform EC key agreement
		var encryptionKey = this.generateSymmetricKey(challengeKeyPair, other.getPublicKey());
		System.out.println("Challenge computed enc key: "+hex.formatHex(encryptionKey.getEncoded()));
		
		// create 128 bit IV / GCM etc
		byte[] ivRaw = new byte[12];
		SecureRandom.getInstanceStrong().nextBytes(ivRaw);
		var iv = new IvParameterSpec(ivRaw);

		// encrypt nonce
		Cipher cipher = Cipher.getInstance(ECDHPeer.algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(128, iv.getIV()));
		byte[] encryptedNonce64 = cipher.doFinal(nonce64);
		System.out.println("Encrypted Challenge: "+hex.formatHex(encryptedNonce64));
		
		// SHA-256 HMAC the encrypted nonce
		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(new SecretKeySpec(encryptionKey.getEncoded(), "HmacSHA256"));
		var cipherNonceHMAC = hmac.doFinal(encryptedNonce64);
		
		// populate a PoP structure
		PoP pop = new PoP(
				hex.formatHex(encryptedNonce64),
				challengeKeyPair.getPublic(),
				hex.formatHex(iv.getIV()),
				hex.formatHex(cipherNonceHMAC),
				"HmacSHA256",
				ECDHPeer.algorithm);
		
		var response = other.createPoPResponse(pop);

		System.out.println("\nPerforming PoP Validation ....");
		
		if ( response.isEmpty() )
			return false;

		System.out.println("Response Received\n=================");
		printPoP(response.get());
		
		// use the public key provided in the response, along with the private key used for the challenge
		// to create a shared secret 

		// Perform EC key agreement
		var vEncryptionKey = this.generateSymmetricKey(challengeKeyPair, response.get().publicKey());
		System.out.println("Validation computed enc key: "+hex.formatHex(vEncryptionKey.getEncoded()));
		
		// use it calc hmac of response nonce, if matches response hmac ok
		Mac vHMAC = Mac.getInstance("HmacSHA256");
		vHMAC.init(new SecretKeySpec(vEncryptionKey.getEncoded(), "HmacSHA256"));
		var vCipherNonceHMAC = hmac.doFinal(hex.parseHex(response.get().encryptedNonce()));
		
		var suppliedHMAC = hex.parseHex(response.get().hmac());
		
		// validate hmac of decoded nonce
		var vHMACMatch = Arrays.equals(vCipherNonceHMAC, suppliedHMAC);
		if ( !vHMACMatch ) {
			System.err.println("HMAC mismatch in response from other");
			return false;
		}
		
		// decrypt the encrypted response using IV from response
		var vIV = new IvParameterSpec(hex.parseHex(response.get().iv()));
		
		Cipher vCipher = Cipher.getInstance(response.get().algorithm());
		vCipher.init(Cipher.DECRYPT_MODE, vEncryptionKey, new GCMParameterSpec(128, vIV.getIV()));
		byte[] vNonce64 = vCipher.doFinal(hex.parseHex(response.get().encryptedNonce()));
		var vRawNonce = Base64.getDecoder().decode(vNonce64);
		
		// if first 256 bytes match nonce then peer holds the private key they claim to
		var nonceMatch = Arrays.equals(vRawNonce,rawNonce);
		if ( !nonceMatch ) {
			System.err.println("Challenge mismatch in response from other");
			return false;
		} else 
			return true;
		
	}

	/**
	 * Called by challengers to determine if this instance of ECDHPeer holds the private key
	 * that corresponds to the public key used to encrypt the nonce in the challenge object.
	 * 
	 * @param challenge
	 * @return a populated Optional with the response to the challenge unless tampering was detected
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public Optional<PoP> createPoPResponse(PoP challenge) 
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, 
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {


		System.out.println("\nPerforming PoP Response ....");
		Optional<PoP> response = Optional.empty();
		var hex = HexFormat.of();
		
		System.out.println("Challenge Received\n==================");
		printPoP(challenge);
		
		// Perform EC key agreement
		var encryptionKey = this.generateSymmetricKey(myKeyPair, challenge.publicKey());
		System.out.println("Response computed enc key: "+hex.formatHex(encryptionKey.getEncoded()));
		
		// SHA-256 HMAC the encrypted nonce
		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(new SecretKeySpec(encryptionKey.getEncoded(), "HmacSHA256"));
		var cipherNonceHMAC = hmac.doFinal(hex.parseHex(challenge.encryptedNonce()));
		System.out.println("HMAC calculated as: "+hex.formatHex(cipherNonceHMAC));
		
		var suppliedHMAC = hex.parseHex(challenge.hmac());
		
		// validate hmac of decoded nonce
		var hmacMatch = Arrays.equals(cipherNonceHMAC, suppliedHMAC);
		if ( !hmacMatch ) {
			System.err.println("HMAC fail building response - tampering?");
			return response;
		}
		
		// decrypt nonce using IV from challenge
		var iv = new IvParameterSpec(hex.parseHex(challenge.iv()));
		Cipher cipher = Cipher.getInstance(challenge.algorithm());
		cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(128, iv.getIV()));
		byte[] nonce64 = cipher.doFinal(hex.parseHex(challenge.encryptedNonce()));
		var rawNonce = Base64.getDecoder().decode(nonce64);
		
		// create new ephemeral pair and use its private key and the public key in challenge
		// to generate a symmetric key, to encrypt the nonce back again
		
		// create ephemeral keypair
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		KeyPair responseKeyPair = keyPairGen.generateKeyPair();

		// Perform EC key agreement
		var epEncryptionKey = this.generateSymmetricKey(responseKeyPair, challenge.publicKey());
		System.out.println("Response computed validation enc key: "+hex.formatHex(epEncryptionKey.getEncoded()));
		
		// create 128 bit IV 
		byte[] ivRaw = new byte[12];
		SecureRandom.getInstanceStrong().nextBytes(ivRaw);
		var rIV = new IvParameterSpec(ivRaw);

		// encrypt nonce with new key
		Cipher epCipher = Cipher.getInstance(ECDHPeer.algorithm);
		epCipher.init(Cipher.ENCRYPT_MODE, epEncryptionKey, new GCMParameterSpec(128, rIV.getIV()));
		byte[] encryptedNonce64 = epCipher.doFinal(nonce64);
		
		// SHA-256 HMAC the encrypted nonce
		Mac rHMAC = Mac.getInstance("HmacSHA256");
		rHMAC.init(new SecretKeySpec(epEncryptionKey.getEncoded(), "HmacSHA256"));
		var rCipherNonceHMAC = hmac.doFinal(encryptedNonce64);
		
		// populate a PoP structure
		response = Optional.of(new PoP(
				hex.formatHex(encryptedNonce64),
				responseKeyPair.getPublic(),
				hex.formatHex(rIV.getIV()),
				hex.formatHex(rCipherNonceHMAC),
				"HmacSHA256",
				ECDHPeer.algorithm));
		
		return response;
	}
	
	/**
	 * DRY helper - should write a test ...
	 * 
	 * @param myKeys
	 * @param peerPublicKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private SecretKey generateSymmetricKey(KeyPair myKeys, PublicKey peerPublicKey) 
			throws NoSuchAlgorithmException, InvalidKeyException {
		
		// Perform key agreement
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(myKeys.getPrivate());
		ka.doPhase(peerPublicKey, true);

		// Generate shared secret
		byte[] sharedSecret = ka.generateSecret();

		// Derive a key from the shared secret and both public keys
		// NIST SP 800-56A revision 2 says a HMAC SHA-256 would be a good kdf
		// we're using a md rather than hmac
		// md verifies integrity of a message
		// hmac verifies integrity and authenticity of a message
		// need to look into this more .... OP did say not to use in production
		// ECIES says the EC generated shared secret should be stretched using a kdf
		// one is used to encrypt the message later and the other to feed hmac
		// we should really have a version of this for ECIES
		
		MessageDigest hash = MessageDigest.getInstance("SHA-256");
		hash.update(sharedSecret);

		// Reusable deterministic ordering
		List<ByteBuffer> keys = 
				Arrays.asList(
						ByteBuffer.wrap(myKeys.getPublic().getEncoded()), 
						ByteBuffer.wrap(peerPublicKey.getEncoded()));

		Collections.sort(keys);
		hash.update(keys.get(0));
		hash.update(keys.get(1));

		return new SecretKeySpec(hash.digest(),"AES");
	}
	
	// https://www.nominet.uk/how-elliptic-curve-cryptography-encryption-works/
	// have a version of above for ECIES use
	// where generated EC secret is stretched to 256 bits using hmac sha256
	// or rather PBKDF2WithHmacSHA256 from the secretkey factory
	
	public record ECPoP(
			String encryptedNonce, // hex string of byte[] 
			PublicKey publicKey, // should really make this a string with the hex public key bytes in it
			String iv, // hex string of byte[]
			String hmac, // hex string of byte[]
			String kdf, // text 
			String algorithm // text
			) {}
	
	private ECPoP ECIES_Encrypt(byte[] message, KeyPair myKeys, PublicKey peerPublicKey,
			String algorithm, String kdf) 
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
			BadPaddingException {
				
		var rawSecret = ECIES_CalcKey(myKeys.getPrivate(), peerPublicKey);
		var encRaw = Arrays.copyOfRange(rawSecret, 0, 16);
		var macRaw = Arrays.copyOfRange(rawSecret, 16, 32);
		
		var encryptionKey = new SecretKeySpec(encRaw,"AES");
		var hmacKey = new SecretKeySpec(macRaw,"AES");
		
		// create 128 bit IV / GCM etc
		byte[] ivRaw = new byte[12];
		SecureRandom.getInstanceStrong().nextBytes(ivRaw);
		var iv = new IvParameterSpec(ivRaw);

		// encrypt nonce
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(128, iv.getIV()));
		byte[] encryptedMessage = cipher.doFinal(message);
		
		// SHA-256 HMAC the encrypted nonce
		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(new SecretKeySpec(hmacKey.getEncoded(), "HmacSHA256"));
		var encryptedMessageHMAC = hmac.doFinal(encryptedMessage);
		
		var hex = HexFormat.of();
		
		return new ECPoP(
				hex.formatHex(encryptedMessage),
				myKeys.getPublic(),
				hex.formatHex(ivRaw),
				hex.formatHex(encryptedMessageHMAC),
				"PBKDF2WithHmacSHA256",
				algorithm);
	}
	
	private byte[] ECIES_Decrypt(ECPoP challenge, PrivateKey myPrivateKey) 
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
			BadPaddingException {
	
		var hex = HexFormat.of();

		var rawSecret = ECIES_CalcKey(myPrivateKey, challenge.publicKey);
		var encRaw = Arrays.copyOfRange(rawSecret, 0, 16);
		var macRaw = Arrays.copyOfRange(rawSecret, 16, 32);
		
		var encryptionKey = new SecretKeySpec(encRaw,"AES");
		var hmacKey = new SecretKeySpec(macRaw,"AES");
		
		// derive HMAC of message and check it matches 
		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(new SecretKeySpec(hmacKey.getEncoded(), "HmacSHA256"));
		var encryptedMessageHMAC = hmac.doFinal(hex.parseHex(challenge.encryptedNonce()));
		
		var hmacMatch = Arrays.equals(encryptedMessageHMAC, hex.parseHex(challenge.hmac()));
		
		if ( !hmacMatch ) {
			System.err.println("ECIES_Decrypt: HMAC does not match");
			return null;
		}
		
		// decrypt nonce using IV from challenge
		var iv = new IvParameterSpec(hex.parseHex(challenge.iv()));
		Cipher cipher = Cipher.getInstance(challenge.algorithm());
		cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(128, iv.getIV()));

		return cipher.doFinal(hex.parseHex(challenge.encryptedNonce()));
		
	}
	
	private byte[] ECIES_CalcKey(PrivateKey privateKey, PublicKey publicKey) 
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
		
		// Perform key agreement
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(privateKey);
		ka.doPhase(publicKey, true);

		// Generate shared secret
		byte[] sharedKey = ka.generateSecret();
		
		// perform kdf - only viable one needs a salt - all seems overkill for ephemeral use case
		byte[] salt = new String("salt and pepper?").getBytes(); // 128 bit but is well known a problem?
		var spec = new PBEKeySpec(new String(sharedKey).toCharArray(), salt, 310000, 256); // overkill
		var kdfFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // only one in std java crypto
		var secretKey = kdfFactory.generateSecret(spec);

		return secretKey.getEncoded();
	}
	
	public boolean ECIES_Challenge(ECDHPeer other) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, 
			InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, 
			BadPaddingException {
		
		// get 256 bytes of random 
		byte[] rawNonce = new byte[256]; 
		SecureRandom.getInstanceStrong().nextBytes(rawNonce);
		var nonce64 = Base64.getEncoder().encode(rawNonce); // would have thought base64 encoding after enc was more appropriate
	
		// create challenge keypair
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		KeyPair challengeKeyPair = keyPairGen.generateKeyPair();
		
		var eciesPoP = ECIES_Encrypt(nonce64, challengeKeyPair, other.getPublicKey(), 
				"AES/GCM/NoPadding", "PBKDF2WithHmacSHA256");
		
		var response = other.ECIES_Respond(eciesPoP);
		
		// validate response
		
		var retNonce = ECIES_Decrypt(response, challengeKeyPair.getPrivate());
		
		// if match nonces then peer holds the private key they claim to
		var nonceMatch = Arrays.equals(retNonce,nonce64);
		if ( !nonceMatch ) {
			System.err.println("ECIES_Challenge: response from other does not match");
			return false;
		} else 
			return true;
		
	}
	
	public ECPoP ECIES_Respond(ECPoP eciesPoP) 
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
			BadPaddingException {
		
		var nonce = ECIES_Decrypt(eciesPoP, this.myKeyPair.getPrivate());
		
		if ( nonce == null ) {
			System.err.println("ECIES_Respond: Failed to decrypt challenge");
			return null;
		} 
		
		// create ephemeral keypair
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		KeyPair responseKeyPair = keyPairGen.generateKeyPair();
		
		return ECIES_Encrypt(nonce, responseKeyPair, eciesPoP.publicKey(), 
				"AES/GCM/NoPadding", "PBKDF2WithHmacSHA256");
		
	}
}
