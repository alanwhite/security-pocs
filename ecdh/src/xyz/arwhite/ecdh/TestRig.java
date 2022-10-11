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
		System.out.println("Sginature verification is "+alice.verifyPeer("arwhite.xyz", signature));
	}

}
