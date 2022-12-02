package xyz.arwhite.ecdh;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
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

	// NIST recommends AES-GCM
	// private static final String algorithm = "AES/CBC/PKCS5Padding";
	private static final String algorithm = "AES/GCM/NoPadding";

	private PrivateKey privateKey;
	private PublicKey publicKey;
	private PublicKey peerPublicKey;
	private SecretKey symmetricKey;

	public ECDHPeer() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
		KeyPair keyPair = keyPairGen.generateKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
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
		
		KeyFactory kf = KeyFactory.getInstance("EC");
		X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(peerPublicKey.getEncoded());
		this.peerPublicKey = kf.generatePublic(pkSpec);

		// Perform key agreement
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(privateKey);
		ka.doPhase(this.peerPublicKey, true);

		// Read shared secret
		byte[] sharedSecret = ka.generateSecret();

		// Derive a key from the shared secret and both public keys
		MessageDigest hash = MessageDigest.getInstance("SHA-256");
		hash.update(sharedSecret);

		// Simple deterministic ordering
		List<ByteBuffer> keys = 
				Arrays.asList(
						ByteBuffer.wrap(this.publicKey.getEncoded()), 
						ByteBuffer.wrap(this.peerPublicKey.getEncoded()));

		Collections.sort(keys);
		hash.update(keys.get(0));
		hash.update(keys.get(1));

		this.symmetricKey = new SecretKeySpec(hash.digest(),"AES");

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
}
