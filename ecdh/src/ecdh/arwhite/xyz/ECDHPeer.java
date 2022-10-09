package ecdh.arwhite.xyz;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/***
 * Utility class to encrypt/decrypt data using symmetric key produced as a result of exchanging
 * public keys with another instance. 
 * 
 * No 3rd party dependencies. This makes it lightweight but not battle hardened, link google tink.
 * 
 * So DO NOT USE IN PRODUCTION. This is a learning tool for me.
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

	public ECDHPeer() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(256);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
	}

	public void setPeerPublicKey(byte[] peerPublicKeyEnc) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

		KeyFactory kf = KeyFactory.getInstance("EC");
		X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(peerPublicKeyEnc);
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

	public byte[] getPublicKey() {
		return publicKey.getEncoded();
	}

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

	public String decrypt(String cipherPayload) throws NoSuchPaddingException, NoSuchAlgorithmException,
	InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {

		var blocks = cipherPayload.split("\\.");
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
	


	
}
