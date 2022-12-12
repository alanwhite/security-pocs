package xyz.arwhite.ecdh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ECIES {

	KeyPair localIdentity;
	
	public void setIdentity(KeyPair identity) {
		this.localIdentity = identity;
	}
	
	public PublicKey getPublicKey() {
		return this.localIdentity.getPublic();
	}
	
	public KeyPair generateKeyPair() 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		return keyPairGen.generateKeyPair();

	}

	public record ECPoP(
			String encryptedNonce, // hex string of byte[] 
			String publicKey, // should really make this a string with the hex public key bytes in it
			String iv, // hex string of byte[]
			String hmac, // hex string of byte[]
			String kdf, // text 
			String algorithm // text
			) {}
	
	private ECPoP encrypt(byte[] message, KeyPair myKeys, PublicKey peerPublicKey,
			String algorithm, String kdf) 
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
			BadPaddingException {
				
		var rawSecret = generateSharedSecret(myKeys.getPrivate(), peerPublicKey);
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
				Base64.getEncoder().encodeToString(myKeys.getPublic().getEncoded()),
				hex.formatHex(ivRaw),
				hex.formatHex(encryptedMessageHMAC),
				"PBKDF2WithHmacSHA256",
				algorithm);
	}
	
	private PublicKey toECPublicKey(byte[] encoded) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		var ks = new X509EncodedKeySpec(encoded);
	    var kf = KeyFactory.getInstance("EC");
	    
	    ECPublicKey remotePublicKey = (ECPublicKey)kf.generatePublic(ks);
	    System.out.println(remotePublicKey);
	    
	    return (ECPublicKey)kf.generatePublic(ks);
	}
	
	
	private byte[] decrypt(ECPoP challenge, PrivateKey myPrivateKey) 
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
			BadPaddingException {
	
		var hex = HexFormat.of();
		
		var otherPublic = toECPublicKey(Base64.getDecoder().decode(challenge.publicKey()));
		
		var rawSecret = generateSharedSecret(myPrivateKey, otherPublic);
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
			System.err.println("ECIES.decrypt: HMAC does not match");
			return null;
		}
		
		// decrypt nonce using IV from challenge
		var iv = new IvParameterSpec(hex.parseHex(challenge.iv()));
		Cipher cipher = Cipher.getInstance(challenge.algorithm());
		cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(128, iv.getIV()));

		return cipher.doFinal(hex.parseHex(challenge.encryptedNonce()));
		
	}
	
	private byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) 
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
	
	/**
	 * Comprehensive mechanism for proving the provided peer object does indeed possess
	 * the private key for the public key they advertise.
	 * 
	 * @param other
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public boolean challenge(ECIES other) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, 
			InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, 
			BadPaddingException {
		
		// get 256 bytes of random 
		byte[] rawNonce = new byte[256]; 
		SecureRandom.getInstanceStrong().nextBytes(rawNonce);
		var nonce64 = Base64.getEncoder().encode(rawNonce); // would have thought base64 encoding after enc was more appropriate
	
		// create challenge keypair
		KeyPair challengeKeyPair = this.generateKeyPair();
		
		var eciesPoP = encrypt(nonce64, challengeKeyPair, other.getPublicKey(), 
				"AES/GCM/NoPadding", "PBKDF2WithHmacSHA256");
		
		var response = other.respond(eciesPoP);
		
		// validate response
		
		var retNonce = decrypt(response, challengeKeyPair.getPrivate());
		
		// if match nonces then peer holds the private key they claim to
		var nonceMatch = Arrays.equals(retNonce,nonce64);
		if ( !nonceMatch ) {
			System.err.println("ECIES.challenge: response from other does not match");
			return false;
		} else 
			return true;
		
	}
	
	/**
	 * How to respond to the comprehensive mechanism that's proving this object
	 * possesses the private key that matches the public key it advertises.
	 * 
	 * @param eciesPoP
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public ECPoP respond(ECPoP eciesPoP) 
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
			BadPaddingException {
		
		var nonce = decrypt(eciesPoP, this.localIdentity.getPrivate());
		
		if ( nonce == null ) {
			System.err.println("ECIES.respond: Failed to decrypt challenge");
			return null;
		} 
		
		// create ephemeral keypair
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		KeyPair responseKeyPair = keyPairGen.generateKeyPair();
		
		var otherPublic = toECPublicKey(Base64.getDecoder().decode(eciesPoP.publicKey()));
		
		return encrypt(nonce, responseKeyPair, otherPublic, 
				"AES/GCM/NoPadding", "PBKDF2WithHmacSHA256");
		
	}
	
}
