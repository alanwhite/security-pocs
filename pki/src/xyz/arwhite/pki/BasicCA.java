package xyz.arwhite.pki;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 * Implements a basic CA. Thinking it can work as root or intermediate to any level.
 * 
 * Will see how it develops.
 * 
 * @author Alan R. White
 *
 */
public class BasicCA {

	private KeyStore keyStore;
	
	public BasicCA() throws KeyStoreException {
		keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(stream, password);
	}
	
	private void createRoot() 
			throws NoSuchAlgorithmException, NoSuchProviderException, 
			InvalidKeyException, CertificateException, SignatureException, 
			IOException, KeyStoreException {
		
		CertAndKeyGen certGen = new CertAndKeyGen("RSA","SHA256WithRSA",null);
		certGen.generate(2048);
		long validSecs = (long) 3 * 365 * 24 * 60 * 60; // 3 years
		
		X509Certificate cert = certGen.getSelfCertificate(
				new X500Name("CN=Root CA,O=arwhite,L=Glasgow,C=GB"),
				0);
		
		keyStore.setKeyEntry("root.pki.arwhite.xyz", certGen.getPrivateKey(), null, 
                new X509Certificate[] { cert });
	}

}
