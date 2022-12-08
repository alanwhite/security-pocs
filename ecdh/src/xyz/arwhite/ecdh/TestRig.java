package xyz.arwhite.ecdh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TestRig {
	
	public static void main(String[] args) 
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, 
			IllegalBlockSizeException, SignatureException {
		
		var bob = new ECDHPeer();
		var alice = new ECDHPeer();
		
		bob.setPeerPublicKey(alice.getPublicKey());
		alice.setPeerPublicKey(bob.getPublicKey());
		
		var encrypted = bob.encrypt("arwhite.xyz");
		System.out.println(encrypted);
		var decrypted = alice.decrypt(encrypted);
		System.out.println(decrypted);
		
		var signature = bob.sign("arwhite.xyz");
		System.out.println("Signature verification is "+alice.verifyPeer("arwhite.xyz", signature));
		
		if ( bob.performPoPChallenge(alice) )
			System.out.println("Alice successfully proved possession of their private key");
		
		if ( alice.performPoPChallenge(bob) )
			System.out.println("Bob successfully proved possession of their private key");
		
		var start = System.currentTimeMillis();
		if ( bob.ECIES_Challenge(alice) )
			System.out.println("ECIES: Alice successfully proved possession of their private key");
		var fin = System.currentTimeMillis();
		System.out.println("ECIES took "+(fin-start)+" milliseconds");
		
	}

}
