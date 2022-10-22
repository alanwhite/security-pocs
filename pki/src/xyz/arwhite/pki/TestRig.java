package xyz.arwhite.pki;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class TestRig {

	public TestRig() {
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) 
			throws InvalidKeyException, UnrecoverableKeyException, KeyStoreException, 
			NoSuchAlgorithmException, CertificateException, NoSuchProviderException, 
			SignatureException, IOException {
		
		var ca = new BasicCA();

	}

}
