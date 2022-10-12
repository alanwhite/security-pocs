package xyz.arwhite.pki;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
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

	private final String ROOTKEYSTORENAME = "/tmp/arw-root.jks";
	private final String ROOTCERTKEY = "root.pki.arwhite.xyz";
	private final String ROOTX500NAME = "CN=ARWRootCA,O=arwhite,L=Glasgow,C=GB";

	private final String INTERKEYSTORENAME = "/tmp/arw-signers.jks";
	private final String SERVERCERTKEY = "servers.pki.arwhite.xyz";
	private final String SERVERX500NAME = "CN=ARWServerCA,O=arwhite,L=Glasgow,C=GB";
	private final String CLIENTCERTKEY = "clients.pki.arwhite.xyz";
	private final String CLIENTX500NAME = "CN=ARWClientCA,O=arwhite,L=Glasgow,C=GB";

	private KeyStore rootKeyStore;

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

		setupKeyStores();
	}

	private void createSelfSignedCert(KeyStore ks, String identity, String key) 
			throws NoSuchAlgorithmException, NoSuchProviderException, 
			InvalidKeyException, CertificateException, SignatureException, 
			IOException, KeyStoreException {

		CertAndKeyGen certGen = new CertAndKeyGen("RSA","SHA256WithRSA",null);
		certGen.generate(2048);
		long validSecs = (long) 3 * 365 * 24 * 60 * 60; // 3 years

		X509Certificate cert = certGen.getSelfCertificate(
				new X500Name(identity),
				0);

		ks.setKeyEntry(key, certGen.getPrivateKey(), null, 
				new X509Certificate[] { cert });
	}

	private KeyStore openOrCreateKeyStore(String name, char[] password) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

		KeyStore keyStore = KeyStore.getInstance("pkcs12");

		try (FileInputStream fis = new FileInputStream(ROOTKEYSTORENAME)) {
			keyStore.load(fis, password);
		} catch (FileNotFoundException e) {
			// We need to create it
			keyStore.load(null, password);
		}

		return keyStore;
	}
	
	private boolean ensureCertExists(KeyStore keyStore, char[] password, String x500Name, String certKey) 
			throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, 
			NoSuchProviderException, CertificateException, SignatureException, FileNotFoundException, 
			IOException {
		
		boolean created = false;
		
		// check if keystore contains cert & if not create it
		if ( !keyStore.containsAlias(ROOTCERTKEY) ) {
			createSelfSignedCert(keyStore,x500Name,certKey);
			created = true;

			try (FileOutputStream fos = new FileOutputStream(ROOTKEYSTORENAME)) {
				keyStore.store(fos, password);
			}
		}
		
		return created;
	}

	/**
	 * Creates the root and intermediate keystores if needed, otherwise uses existing
	 * ones, ensuring cert chain is intact.
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws UnrecoverableKeyException 
	 */
	private void setupKeyStores() 
			throws KeyStoreException, NoSuchAlgorithmException, 
			CertificateException, IOException, NoSuchProviderException, InvalidKeyException, 
			SignatureException, UnrecoverableKeyException {

		boolean signIntermediates = false;

		/*
		 * Root Cert & Key for signing Intermediate CAs Certs  
		 */

		char[] rootPassword = "dumbdumb".toCharArray();
		KeyStore rootKS = openOrCreateKeyStore(ROOTKEYSTORENAME,rootPassword);
		signIntermediates = ensureCertExists(rootKS, rootPassword, ROOTX500NAME, ROOTCERTKEY);
		
		/*
		 * Intermediate Certs & Keys used for signing Client and Server Certs
		 */

		char[] signingPassword = "inthemiddle".toCharArray();
		KeyStore signingKS = openOrCreateKeyStore(INTERKEYSTORENAME,signingPassword);
		signIntermediates = ensureCertExists(signingKS, signingPassword, SERVERX500NAME, SERVERCERTKEY);
		signIntermediates = ensureCertExists(signingKS, signingPassword, CLIENTX500NAME, CLIENTCERTKEY);

		/*
		 * Signing ceremony
		 */

		if ( signIntermediates ) {
			var signingKey = (PrivateKey) rootKS.getKey(ROOTCERTKEY, null);
			var signingCert = (X509Certificate) rootKS.getCertificate(ROOTCERTKEY);
			
			var serverSigningCert = (X509Certificate) signingKS.getCertificate(SERVERCERTKEY);
		
			var clientSigningCert = signingKS.getCertificate(CLIENTCERTKEY);
			
		}


	}
	
	
	// keytool source code
//	
//	public static byte[] sign(PKCS10 csr, X509CertImpl signerCert, PrivateKey signerPrivKey) throws CertificateException, IOException, InvalidKeyException, SignatureException {
//
//	    /*
//	     * The code below is partly taken from the KeyTool class in OpenJDK7.
//	     */
//
//	    X509CertInfo signerCertInfo = (X509CertInfo) signerCert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
//	    X500Name issuer = (X500Name) signerCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);
//
//	    /*
//	     * Set the certificate's validity:
//	     * From now and for VALIDITY_DAYS days 
//	     */
//	    Date firstDate = new Date();
//	    Date lastDate = new Date();
//	    lastDate.setTime(firstDate.getTime() + VALIDITY_DAYS * 1000L * 24L * 60L * 60L);
//	    CertificateValidity interval = new CertificateValidity(firstDate, lastDate);
//
//	    /*
//	     * Initialize the signature object
//	     */
//	    Signature signature;
//	    try {
//	        signature = Signature.getInstance(SIGNATURE_ALGORITHM);
//	    } catch (NoSuchAlgorithmException e) {
//	        throw new RuntimeException(e);
//	    }
//	    signature.initSign(signerPrivKey);
//
//	    /*
//	     * Add the certificate information to a container object
//	     */
//	    X509CertInfo certInfo = new X509CertInfo();
//	    certInfo.set(X509CertInfo.VALIDITY, interval);
//	    certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new Random().nextInt() & 0x7fffffff));
//	    certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//	    try {
//	        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(SIGNATURE_ALGORITHM)));
//	    } catch (NoSuchAlgorithmException e) {
//	        throw new RuntimeException(e);
//	    }
//	    certInfo.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
//	    certInfo.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
//	    certInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(csr.getSubjectName()));
//
//	    /*
//	     * Add x509v3 extensions to the container
//	     */
//	    CertificateExtensions extensions = new CertificateExtensions();
//
//	    // Example extension.
//	    // See KeyTool source for more.
//	    boolean[] keyUsagePolicies = new boolean[9];
//	    keyUsagePolicies[0] = true; // Digital Signature
//	    keyUsagePolicies[2] = true; // Key encipherment
//	    KeyUsageExtension kue = new KeyUsageExtension(keyUsagePolicies);
//	    byte[] keyUsageValue = new DerValue(DerValue.tag_OctetString, kue.getExtensionValue()).toByteArray();
//	    extensions.set(KeyUsageExtension.NAME, new Extension(
//	            kue.getExtensionId(),
//	            true, // Critical
//	            keyUsageValue));
//
//
//	    /*
//	     * Create the certificate and sign it
//	     */
//	    X509CertImpl cert = new X509CertImpl(certInfo);
//	    try {
//	        cert.sign(signerPrivKey, SIGNATURE_ALGORITHM);
//	    } catch (NoSuchAlgorithmException e) {
//	        throw new RuntimeException(e);
//	    } catch (NoSuchProviderException e) {
//	        throw new RuntimeException(e);
//	    }
//
//	    /*
//	     * Return the signed certificate as PEM-encoded bytes
//	     */
//	    ByteOutputStream bos = new ByteOutputStream();
//	    PrintStream out = new PrintStream(bos);
//	    BASE64Encoder encoder = new BASE64Encoder();
//	    out.println(X509Factory.BEGIN_CERT);
//	    encoder.encodeBuffer(cert.getEncoded(), out);
//	    out.println(X509Factory.END_CERT);
//	    out.flush();
//	    return bos.getBytes();
//	}

}
