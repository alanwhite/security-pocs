package xyz.arwhite.pki;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

import sun.security.pkcs10.PKCS10;
import sun.security.provider.X509Factory;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.Extension;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


/**
 * Implements a basic CA. Thinking it can work as root or intermediate to any level.
 * 
 * Will see how it develops.
 * 
 * Thinking needs to provide getCertificateChain returning root and intermediate certs.
 * Allows others to trust certs signed by our intermediates.
 * 
 * We could say hey if we don't detect the intermediate keystore then we need to 
 * generate a root keystore with root selfsigned cert and then gen the intermediate
 * keystore and certs and sign them with the root.
 * 
 * Once all in place we don't need the private key of the root again, unless we add
 * more intermediates.
 * 
 * Is rotating signing certs as horrible as it seems! You need to sign every cert again 
 * that they signed?
 * 
 * @author Alan R. White
 *
 */
public class BasicCA {


	private final String ROOTKEYSTORENAME = "/tmp/arw-root.jks";
	private final String ROOTCERTKEY = "root.pki.arwhite.xyz";
	private final String ROOTX500NAME = "CN=ARWRootCA,O=arwhite,L=Glasgow,C=GB";
	private final long ROOTCERTDAYSVALID = 3 * 365 * 24 * 60 * 60; // 3 years

	private final String INTERKEYSTORENAME = "/tmp/arw-signers.jks";
	private final String SERVERCERTKEY = "servers.pki.arwhite.xyz";
	private final String SERVERX500NAME = "CN=ARWServerCA,O=arwhite,L=Glasgow,C=GB";
	private final long SERVERCERTDAYSVALID = 3 * 365 * 24 * 60 * 60; // 3 years
	
	private final String CLIENTCERTKEY = "clients.pki.arwhite.xyz";
	private final String CLIENTX500NAME = "CN=ARWClientCA,O=arwhite,L=Glasgow,C=GB";
	private final long CLIENTCERTDAYSVALID = 3 * 365 * 24 * 60 * 60; // 3 years
	
	private static final long VALIDITY_DAYS = 14;
	private static final String SIGNATURE_ALGORITHM = null;

	private KeyStore rootKeyStore;
	private PrivateKey serverPrivateKey = null;
	private X500Name serverX500Name = null;
	private PrivateKey clientPrivateKey = null;
	private X500Name clientX500Name = null;

	/**
	 * Constructor ensures there's functioning Root and Intermediate CAs.
	 * 
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws UnrecoverableKeyException 
	 */
	public BasicCA() 
			throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, 
			CertificateException, NoSuchProviderException, SignatureException, IOException, 
			UnrecoverableKeyException {

		boolean createIntermediateCerts = false;

		KeyStore signingKS = KeyStore.getInstance("pkcs12");
		char[] signingPassword = "inthemiddle".toCharArray();
	
		try (FileInputStream fis = new FileInputStream(INTERKEYSTORENAME)) {
			signingKS.load(fis, signingPassword);
			if ( !(signingKS.containsAlias(CLIENTCERTKEY)) || !(signingKS.containsAlias(SERVERCERTKEY)) ) {
				createIntermediateCerts = true;
			}
			
		} catch (FileNotFoundException e) {
			signingKS.load(null, signingPassword);
			createIntermediateCerts = true;
		}

		if ( createIntermediateCerts ) {
			// create root key store
			boolean createRootCert = false;
			
			KeyStore rootKS = KeyStore.getInstance("pkcs12");
			char[] rootPassword = "dumbdumb".toCharArray();
	
			try (FileInputStream fis = new FileInputStream(ROOTKEYSTORENAME)) {
				rootKS.load(fis, rootPassword);
				if ( !(rootKS.containsAlias(ROOTCERTKEY)) ) {
					createRootCert = true;
				}
				
			} catch (FileNotFoundException e) {
				rootKS.load(null, rootPassword);
				createRootCert = true;
			}
			
			PrivateKey rootPrivateKey = null;
			X500Name rootX500Name = null;
			
			if ( createRootCert ) {
				CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null); // self-signed
				certGen.generate(2048);
				rootX500Name = new X500Name(ROOTX500NAME);
				rootPrivateKey = certGen.getPrivateKey();
				X509Certificate cert = certGen.getSelfCertificate(rootX500Name, ROOTCERTDAYSVALID);
				rootKS.setKeyEntry(ROOTCERTKEY, certGen.getPrivateKey(), null, new X509Certificate[] { cert });
			
				try (FileOutputStream fos = new FileOutputStream(ROOTKEYSTORENAME)) {
					rootKS.store(fos, rootPassword);
				}
				
			} else {
				rootPrivateKey = (PrivateKey) rootKS.getKey(ROOTCERTKEY, null);
				var rootCert = (X509Certificate) rootKS.getCertificate(ROOTCERTKEY);
				rootX500Name = new X500Name(rootCert.getSubjectX500Principal().getName());
			}
	
			CertAndKeyGen serverCertGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null, rootPrivateKey, rootX500Name);
			serverCertGen.generate(2048);
			serverX500Name = new X500Name(SERVERX500NAME);
			serverPrivateKey = serverCertGen.getPrivateKey();
			X509Certificate serverCert = serverCertGen.getSelfCertificate(serverX500Name, SERVERCERTDAYSVALID);
			signingKS.setKeyEntry(SERVERCERTKEY, serverCertGen.getPrivateKey(), null, new X509Certificate[] { serverCert });

			CertAndKeyGen clientCertGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null, rootPrivateKey, rootX500Name);
			clientCertGen.generate(2048);
			serverX500Name = new X500Name(CLIENTX500NAME);
			serverPrivateKey = clientCertGen.getPrivateKey();
			X509Certificate clientCert = clientCertGen.getSelfCertificate(serverX500Name, SERVERCERTDAYSVALID);
			signingKS.setKeyEntry(CLIENTCERTKEY, clientCertGen.getPrivateKey(), null, new X509Certificate[] { clientCert });
		
			try (FileOutputStream fos = new FileOutputStream(INTERKEYSTORENAME)) {
				signingKS.store(fos, signingPassword);
			}

			
		} else {
			serverPrivateKey = (PrivateKey) signingKS.getKey(SERVERCERTKEY, null);
			var serverCert = (X509Certificate) signingKS.getCertificate(SERVERCERTKEY);
			serverX500Name = new X500Name(serverCert.getSubjectX500Principal().getName());
			
			clientPrivateKey = (PrivateKey) signingKS.getKey(CLIENTCERTKEY, null);
			var clientCert = (X509Certificate) signingKS.getCertificate(CLIENTCERTKEY);
			serverX500Name = new X500Name(clientCert.getSubjectX500Principal().getName());
		}
		
		
	}

	public void signServerCert() {}
	public void signClientCert() {}
	
	public static byte[] sign(PKCS10 csr, X509CertImpl signerCert, PrivateKey signerPrivKey) 
			throws CertificateException, IOException, InvalidKeyException, SignatureException {

	    /*
	     * The code below is partly taken from the KeyTool class in OpenJDK7.
	     */

	    X509CertInfo signerCertInfo = (X509CertInfo) signerCert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
	    X500Name issuer = (X500Name) signerCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);

	    /*
	     * Set the certificate's validity:
	     * From now and for VALIDITY_DAYS days 
	     */
	    Date firstDate = new Date();
	    Date lastDate = new Date();
	    lastDate.setTime(firstDate.getTime() + VALIDITY_DAYS * 1000L * 24L * 60L * 60L);
	    CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

	    /*
	     * Initialize the signature object
	     */
	    Signature signature;
	    try {
	        signature = Signature.getInstance(SIGNATURE_ALGORITHM);
	    } catch (NoSuchAlgorithmException e) {
	        throw new RuntimeException(e);
	    }
	    signature.initSign(signerPrivKey);

	    /*
	     * Add the certificate information to a container object
	     */
	    X509CertInfo certInfo = new X509CertInfo();
	    certInfo.set(X509CertInfo.VALIDITY, interval);
	    certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new Random().nextInt() & 0x7fffffff));
	    certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
	    try {
	        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(SIGNATURE_ALGORITHM)));
	    } catch (NoSuchAlgorithmException e) {
	        throw new RuntimeException(e);
	    }
	    certInfo.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
	    certInfo.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
	    certInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(csr.getSubjectName()));

	    /*
	     * Add x509v3 extensions to the container
	     */
	    CertificateExtensions extensions = new CertificateExtensions();

	    // Example extension.
	    // See KeyTool source for more.
	    boolean[] keyUsagePolicies = new boolean[9];
	    keyUsagePolicies[0] = true; // Digital Signature
	    keyUsagePolicies[2] = true; // Key encipherment
	    KeyUsageExtension kue = new KeyUsageExtension(keyUsagePolicies);
	    byte[] keyUsageValue = new DerValue(DerValue.tag_OctetString, kue.getExtensionValue()).toByteArray();
	    extensions.set(KeyUsageExtension.NAME, new Extension(
	            kue.getExtensionId(),
	            true, // Critical
	            keyUsageValue));


	    /*
	     * Create the certificate and sign it
	     */
	    X509CertImpl cert = new X509CertImpl(certInfo);
	    try {
	        cert.sign(signerPrivKey, SIGNATURE_ALGORITHM);
	    } catch (NoSuchAlgorithmException e) {
	        throw new RuntimeException(e);
	    } catch (NoSuchProviderException e) {
	        throw new RuntimeException(e);
	    }

	    /*
	     * Return the signed certificate as PEM-encoded bytes
	     */
	    ByteArrayOutputStream bos = new ByteArrayOutputStream();
	    PrintStream out = new PrintStream(bos);
	    out.println(X509Factory.BEGIN_CERT);
	    out.println(new String(Base64.getEncoder().encode(cert.getEncoded())));
	    out.println(X509Factory.END_CERT);
	    out.flush();
	    return bos.toByteArray();
	}

}
