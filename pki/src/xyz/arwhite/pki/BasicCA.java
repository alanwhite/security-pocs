package xyz.arwhite.pki;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.Random;

import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs10.PKCS10;
import sun.security.provider.X509Factory;
import sun.security.util.SignatureUtil;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


/**
 * Implements a basic CA. Thinking it can work as root or intermediate to any level.
 * 
 * Will see how it develops.
 * 
 * TODO
 * 1. Thinking needs to provide getCertificateChain returning root and intermediate certs.
 * Allows others to trust certs signed by our intermediates. Seems that the server or client
 * should provide any needed intermediary certs. The peer should have the root cert in their
 * trust store, to be able verify the provided intermediary and peer cert.
 * 
 * We could say hey if we don't detect the intermediate keystore then we need to 
 * generate a root keystore with root selfsigned cert and then gen the intermediate
 * keystore and certs and sign them with the root.
 * 
 * Once all in place we don't need the private key of the root again, unless we add
 * more intermediates. Maybe we should gen another intermediate for playing with
 * MITM intercepting proxy that signs certs on the fly.
 * 
 * Is rotating signing certs as horrible as it seems! You need to sign every cert again 
 * that they signed? Ah hmmm needs cross-signing, got it. Allows transition. More work TBD!
 * 
 * @author Alan R. White
 *
 */
public class BasicCA {

	private record CertEntry(PrivateKey privateKey, X509CertImpl certificate) {};

	private static final String ROOTKEYSTORENAME = "/tmp/arw-root.jks";
	private static final String ROOTCERTKEY = "root.pki.arwhite.xyz";
	private static final String ROOTX500NAME = "CN=ARWRootCA,O=arwhite,L=Glasgow,C=GB";
	private static final long ROOT_CERT_SECONDS_VALID = 3 * 365 * 24 * 60 * 60; // 3 years

	private static final String INTERKEYSTORENAME = "/tmp/arw-signers.jks";
	private static final String SERVERCERTKEY = "servers.pki.arwhite.xyz";
	private static final String SERVERX500NAME = "CN=ARWServerCA,O=arwhite,L=Glasgow,C=GB";
	private static final long SERVER_SIGNING_CERT_SECONDS_VALID = 1 * 365 * 24 * 60 * 60; // 1 year
	private static final long SERVER_CERT_SECONDS_VALID = 1 * 28 * 24 * 60 * 60; // 28 days
	
	private static final String CLIENTCERTKEY = "clients.pki.arwhite.xyz";
	private static final String CLIENTX500NAME = "CN=ARWClientCA,O=arwhite,L=Glasgow,C=GB";
	private static final long CLIENT_SIGNING_CERT_SECONDS_VALID = 1 * 365 * 24 * 60 * 60; // 1 year
	private static final long CLIENT_CERT_SECONDS_VALID = 1 * 28 * 24 * 60 * 60; // 28 days

	private static final long VALIDITY_DAYS = 7;
	private static final String SIGNATURE_ALGORITHM = null;

	private X509CertImpl rootCert;

	private KeyStore certSigningKS;

	private PrivateKey serverPrivateKey = null;
	private X509CertImpl serverSigningCert = null;
	private X500Name serverX500Name = null;

	private PrivateKey clientPrivateKey = null;
	private X509CertImpl clientSigningCert = null;
	private X500Name clientX500Name = null;

	/**
	 * Constructor ensures there's functioning Root and Intermediate CAs.
	 * Reuses the keystores if they exist, if not, creates them.
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

		certSigningKS = KeyStore.getInstance("pkcs12");
		char[] signingPassword = "inthemiddle".toCharArray();

		try (FileInputStream fis = new FileInputStream(INTERKEYSTORENAME)) {
			certSigningKS.load(fis, signingPassword);
			if ( !(certSigningKS.containsAlias(CLIENTCERTKEY)) || !(certSigningKS.containsAlias(SERVERCERTKEY)) ) {
				createIntermediateCerts = true;
			}

		} catch (FileNotFoundException e) {
			certSigningKS.load(null, signingPassword);
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

			// we never need this after setup
			PrivateKey rootPrivateKey = null;

			if ( createRootCert ) {
				var keyGen = KeyPairGenerator.getInstance("RSA");
				var rootKeyPair = keyGen.generateKeyPair();
				rootPrivateKey = rootKeyPair.getPrivate();

				var rootCert = this.createRootCACert(new X500Name(ROOTX500NAME), rootKeyPair, ROOT_CERT_SECONDS_VALID);
				this.rootCert = rootCert.certificate();

				rootKS.setKeyEntry(ROOTCERTKEY, rootCert.privateKey(), 
						null, new X509Certificate[] { rootCert.certificate() });

				try (FileOutputStream fos = new FileOutputStream(ROOTKEYSTORENAME)) {
					rootKS.store(fos, rootPassword);
				}

			} else {
				rootPrivateKey = (PrivateKey) rootKS.getKey(ROOTCERTKEY, null);
				rootCert = (X509CertImpl) rootKS.getCertificate(ROOTCERTKEY);
			}

			var keyGen = KeyPairGenerator.getInstance("RSA");
			var serverKeyPair = keyGen.generateKeyPair();
			var serverCert = this.createIntermediateCACert(new X500Name(SERVERX500NAME), serverKeyPair, 
					rootPrivateKey, rootCert, SERVER_SIGNING_CERT_SECONDS_VALID);

			certSigningKS.setKeyEntry(SERVERCERTKEY, serverCert.privateKey(), 
					null, new X509Certificate[] { serverCert.certificate() });

			var clientKeyPair = keyGen.generateKeyPair();
			var clientCert = this.createIntermediateCACert(new X500Name(CLIENTX500NAME), clientKeyPair, 
					rootPrivateKey, rootCert, CLIENT_SIGNING_CERT_SECONDS_VALID);
			
			certSigningKS.setKeyEntry(CLIENTCERTKEY, clientCert.privateKey(), 
					null, new X509Certificate[] { clientCert.certificate() });

			try (FileOutputStream fos = new FileOutputStream(INTERKEYSTORENAME)) {
				certSigningKS.store(fos, signingPassword);
			}

		} 
		
		serverPrivateKey = (PrivateKey) certSigningKS.getKey(SERVERCERTKEY, null);
		var serverCert = (X509Certificate) certSigningKS.getCertificate(SERVERCERTKEY);
		serverX500Name = new X500Name(serverCert.getSubjectX500Principal().getName());

		clientPrivateKey = (PrivateKey) certSigningKS.getKey(CLIENTCERTKEY, null);
		var clientCert = (X509Certificate) certSigningKS.getCertificate(CLIENTCERTKEY);
		serverX500Name = new X500Name(clientCert.getSubjectX500Principal().getName());

	}

	private CertEntry createRootCACert(
			X500Name subject, 
			KeyPair certKeyPair,
			long validSeconds) 
					throws CertificateException, IOException, NoSuchAlgorithmException, 
					InvalidKeyException, NoSuchProviderException, SignatureException {

		return createCACert(subject, certKeyPair, Optional.empty(), Optional.empty(), validSeconds);
	}
	
	private CertEntry createIntermediateCACert(
			X500Name subject, 
			KeyPair certKeyPair,
			PrivateKey signingKey, // must be present if signingCert present
			X509CertImpl signingCert,
			long validSeconds) 
					throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

		return createCACert(subject, certKeyPair, 
				Optional.of(signingKey), Optional.of(signingCert), validSeconds);

	}
	
	/**
	 * Creates a root or intermediate CA cert 
	 * @param subject X500Name for the DN
	 * @param certKeyPair The public key is embedded in the resultant cert, the private key signs the cert if no signingCert provided
	 * @param signingKey root CA private key if an intermediate CA cert is required 
	 * @param signingCert root CA cert if an intermediate CA cert is required
	 * @param validSeconds how long the resultant cert is to be valid for
	 * @return The certificate and it's private key
	 * @throws CertificateException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 */
	private CertEntry createCACert(
			X500Name subject, 
			KeyPair certKeyPair,
			Optional<PrivateKey> signingKey, // must be present if signingCert present
			Optional<X509CertImpl> signingCert,
			long validSeconds) 
					throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

		X509CertImpl cert = null;

		// keys for cert
		var certPublicKey = certKeyPair.getPublic();
		var certPrivateKey = certKeyPair.getPrivate();

		// valid lifetime
		CertificateValidity interval = this.getCertificateValidity(new Date(), validSeconds);

		// signingCert Info
		// X509CertInfo signerCertInfo = (X509CertInfo) signingCert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
		// X500Name issuer = (X500Name) signerCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);

		// extensions
		CertificateExtensions extensions = new CertificateExtensions();

		// Key Usage Extension
		KeyUsageExtension kue = new KeyUsageExtension(); // sets critical=true;
		kue.set(KeyUsageExtension.KEY_CERTSIGN, true); // RFC5280 MUST be set on CA certs
		extensions.set(KeyUsageExtension.IDENT, kue);

		// basic constraints - if rootCA allow 1 level more of cert signing, else none for intermediates
		BasicConstraintsExtension bce = 
				new BasicConstraintsExtension(true, signingCert.isPresent() ? 0 : 1);
		extensions.set(BasicConstraintsExtension.IDENT, bce);

		X509CertInfo info = new X509CertInfo();

		// Add all mandatory attributes
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		info.set(X509CertInfo.SERIAL_NUMBER, CertificateSerialNumber.newRandom64bit(new SecureRandom()));
		info.set(X509CertInfo.SUBJECT, subject);
		info.set(X509CertInfo.KEY, new CertificateX509Key(certPublicKey));
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.EXTENSIONS, extensions);

		var signWith = certPrivateKey;

		if ( signingCert.isPresent() ) {
			// sign with provided key to build intermediate CA cert
			info.set(X509CertInfo.ISSUER, new X500Name(signingCert.get().getSubjectDN().getName()));

			info.set(X509CertInfo.ALGORITHM_ID, 
					new CertificateAlgorithmId(AlgorithmId.get(
							SignatureUtil.getDefaultSigAlgForKey(signingKey.get()))));

			signWith = signingKey.get();

		} else {
			
			// issuer same as subject for self-signed
			info.set(X509CertInfo.ISSUER, subject);
			
			// self-sign for rootCA
			info.set(X509CertInfo.ALGORITHM_ID, 
					new CertificateAlgorithmId(AlgorithmId.get(
							SignatureUtil.getDefaultSigAlgForKey(certPrivateKey))));

			// seems we need an issuer in there, even for self-signed?
		}

		cert = this.signCert(info, signWith); 

		return new CertEntry(certPrivateKey, cert);
	}

	public X509CertImpl signCert(X509CertInfo info, PrivateKey privateKey) 
			throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, 
			NoSuchProviderException, SignatureException {

		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(privateKey, SignatureUtil.getDefaultSigAlgForKey(privateKey));
		return cert;
	}

	public CertificateValidity getCertificateValidity(Date startDate, long validSeconds) {
		var endDate = new Date();
		endDate.setTime(startDate.getTime() + (validSeconds * 1000) );
		return new CertificateValidity(startDate, endDate);
	}

	public void issueServerCert(PKCS10 csr) 
			throws CertificateException, IOException, NoSuchAlgorithmException {
		
		var issuer = new X500Name(serverSigningCert.getSubjectX500Principal().getName());
		CertificateValidity interval = this.getCertificateValidity(new Date(), SERVER_CERT_SECONDS_VALID);
		
		var csrAttributes = csr.getAttributes();
		var exts = (CertificateExtensions) csrAttributes.getAttribute(PKCS9Attribute.EXTENSION_REQUEST_OID.toString());
		
		var info = new X509CertInfo();		
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		info.set(X509CertInfo.SERIAL_NUMBER, CertificateSerialNumber.newRandom64bit(new SecureRandom()));
		info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(csr.getSubjectName()));
		info.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.EXTENSIONS, exts);
		info.set(X509CertInfo.ISSUER, issuer); 
		
		
	}
	
	public void issueClientCert(PKCS10 csr) {
		
	}

	// ARW mostly harvested from some stackoverflow post
	public static byte[] sign(PKCS10 csr, X509CertImpl signerCert, PrivateKey signerPrivKey) 
			throws CertificateException, IOException, InvalidKeyException, SignatureException, 
			NoSuchAlgorithmException, NoSuchProviderException {

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
		certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(SIGNATURE_ALGORITHM)));
		certInfo.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
		certInfo.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
		certInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(csr.getSubjectName()));

		/*
		 * Add x509v3 extensions to the container
		 */
		CertificateExtensions extensions = new CertificateExtensions();

		// Key Usage Extension
		KeyUsageExtension kue = new KeyUsageExtension(); // sets critical=true;
		kue.set(KeyUsageExtension.DIGITAL_SIGNATURE, true); // not on CA certs RFC5280
		kue.set(KeyUsageExtension.KEY_ENCIPHERMENT, true); // is this needed?	
		kue.set(KeyUsageExtension.KEY_AGREEMENT, true); // not on CA certs RFC5280
		kue.set(KeyUsageExtension.KEY_CERTSIGN, true); // RFC5280 MUST be set on CA certs, and isCA true in basic contraints

		extensions.set(KeyUsageExtension.IDENT, kue);

		// basic constraints
		// BasicConstraintsExtension bce = new BasicConstraintsExtension();

		certInfo.set(X509CertInfo.EXTENSIONS, extensions);

		//	    byte[] keyUsageValue = new DerValue(DerValue.tag_OctetString, kue.getExtensionValue()).toByteArray();
		//	    extensions.set(KeyUsageExtension.NAME, new Extension(
		//	            kue.getExtensionId(),
		//	            true, // Critical
		//	            keyUsageValue));


		/*
		 * Create the certificate and sign it
		 */
		X509CertImpl cert = new X509CertImpl(certInfo);
		cert.sign(signerPrivKey, SIGNATURE_ALGORITHM);


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

	//	ARW- Harvested from https://stackoverflow.com/questions/49985805/add-key-usage-to-certificatesigninginfo-in-java
	//	import sun.security.pkcs.*;
	//	import sun.security.pkcs10.*; // separate in j8 (and later? not checked) 
	//	import sun.security.util.*;
	//	import sun.security.x509.*;
	//
	//	    // dummy setup; replace as appropriate
	//	    X500Name name = new X500Name("O=Widgets Inc, CN=testcert");
	//	    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
	//	    gen.initialize(1024); KeyPair pair = gen.generateKeyPair();
	//	    
	//	    KeyUsageExtension ku = new KeyUsageExtension();
	//	    ku.set(KeyUsageExtension.NON_REPUDIATION, true);
	//	    ku.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);
	//	    ku.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
	//	    CertificateExtensions exts = new CertificateExtensions();
	//	    exts.set(KeyUsageExtension.IDENT,ku);
	//	    PKCS10Attribute extreq = new PKCS10Attribute (PKCS9Attribute.EXTENSION_REQUEST_OID, exts);
	//	    
	//	    PKCS10 csr = new PKCS10 (pair.getPublic(), new PKCS10Attributes (new PKCS10Attribute[]{ extreq }));
	//	    Signature signer = Signature.getInstance("SHA256withRSA"); // or adapt to key 
	//	    signer.initSign(pair.getPrivate());
	//	    csr.encodeAndSign(name, signer);
	//
	//	    // dummy output; replace 
	//	    FileOutputStream out = new FileOutputStream ("SO49985805.der");
	//	    out.write(csr.getEncoded()); out.close();
}
