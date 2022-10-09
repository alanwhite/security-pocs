package pki.arwhite.xyz;

import java.io.IOException;
import java.security.InvalidKeyException;
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

	public BasicCA() {
		// TODO Auto-generated constructor stub
	}
	
	private void play() 
			throws NoSuchAlgorithmException, NoSuchProviderException, 
			InvalidKeyException, CertificateException, SignatureException, IOException {
		
		CertAndKeyGen certGen = new CertAndKeyGen("RSA","SHA256WithRSA",null);
		X509Certificate cert = certGen.getSelfCertificate(
				new X500Name("CN=My App,O=My Org,L=My City,C=GB"),
				0);
		
		
	}

}
