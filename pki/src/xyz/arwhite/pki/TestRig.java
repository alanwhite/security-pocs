package xyz.arwhite.pki;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.Optional;

import javax.naming.ldap.LdapName;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import sun.security.pkcs10.PKCS10;
import sun.security.util.SignatureUtil;
import sun.security.x509.X500Name;

public class TestRig {

	private static final String CA_TRUSTSTORE_NAME = "/tmp/arw-root-cert.jks";

	private static final String SERVER_KEYSTORE_NAME = "/tmp/arw-server.jks";
	private static final String SERVER_CERT_KEY = "active.auth.arwhite.xyz";

	private static final String CLIENT_KEYSTORE_NAME = "/tmp/arw-client.jks";
	private static final String CLIENT_CERT_KEY = "active.auth.arwhite.xyz";

	private static final String URI_RESOURCE = "/v1/foo/";
	private static final int HTTPS_PORT = 8000;

	private BasicCA ca;
	private HttpsServer server;

	public TestRig() 
			throws InvalidKeyException, UnrecoverableKeyException, KeyStoreException, 
			NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, 
			IOException, InterruptedException, KeyManagementException {

		/*
		 * Set up our CA
		 */
		ca = new BasicCA();

	}

	private void runServer() 
			throws KeyStoreException, IOException, KeyManagementException, 
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, 
			InvalidKeyException, SignatureException, NoSuchProviderException {

		/*
		 * Need to gen a cert for this server, and get it signed
		 * -----------------------------------------------------
		 * keytool -alias active.auth.arwhite.xyz -dname "cn=localhost, ou=Java, o=Oracle, c=IN" \
		 * 		-genkeypair -storepass passphrase -keyalg RSA -keystore arw-server.jks
		 * 
		 * Then create a CSR
		 * -----------------
		 * keytool -certreq -alias active.auth.arwhite.xyz -keystore arw-server.jks \
		 * 		-storepass passphrase -keyalg rsa -file server.csr
		 * 
		 * Generate a cert based on the CSR, that is signed by the intermediate
		 * --------------------------------------------------------------------
		 * keytool -gencert -keystore arw-signers.jks -storepass inthemid -alias servers.pki.arwhite.xyz \
		 * 		-infile server.csr -outfile server.cer
		 * NB you need to provide rubbish1 at the prompt for the key entry password, and can't provide 
		 * on command line because it's a pkcs12 store .... who knows!
		 * 
		 * Get the signed cert in the keystore the server will use
		 * -------------------------------------------------------
		 * keytool -importcert -keystore arw-server.jks -storepass passphrase -file server.cer\
		 * 		-alias active.auth.arwhite.xyz
		 * Reply yes to the bizarre prompt
		 */

		/*
		 * Prepare key & cert store the https listener will use
		 */
		var passphrase = "passphrase".toCharArray();
		var serverKS = KeyStore.getInstance("pkcs12");

		var getSignedCert = false;
		try (FileInputStream fis = new FileInputStream(SERVER_KEYSTORE_NAME)) {
			serverKS.load(fis, passphrase);
			if ( !(serverKS.containsAlias(SERVER_CERT_KEY)) || !(serverKS.containsAlias(SERVER_CERT_KEY)) ) {
				getSignedCert = true;
			}

		} catch (FileNotFoundException e) {
			serverKS.load(null, passphrase);
			getSignedCert = true;
		}

		if ( getSignedCert ) {
			// build pkcs10 csr and get it signed by BasicCA

			// Need to gen a CSR for the id of this server (localhost)
			var keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			var certKeyPair = keyGen.generateKeyPair();

			var csr = new PKCS10(certKeyPair.getPublic());
			var name = new X500Name("CN=localhost,O=arwhite,L=Glasgow,C=GB");
			csr.encodeAndSign(name, certKeyPair.getPrivate(), SignatureUtil.getDefaultSigAlgForKey(certKeyPair.getPrivate()));

			var certChain = ca.issueServerCert(csr);
			serverKS.setKeyEntry(SERVER_CERT_KEY, certKeyPair.getPrivate(), 
					passphrase, certChain);

			try (FileOutputStream fos = new FileOutputStream(SERVER_KEYSTORE_NAME)) {
				serverKS.store(fos, passphrase);
			}
		}

		serverKS.load(new FileInputStream(SERVER_KEYSTORE_NAME), passphrase);

		var kmf = KeyManagerFactory.getInstance("PKIX");
		kmf.init(serverKS, passphrase);

		/*
		 * Prepare which CA's certs we will trust when presented by a client
		 */

		KeyStore cacerts = KeyStore.getInstance("pkcs12");
		char[] rootCertPassword = "rootcert".toCharArray();

		try (FileInputStream fis = new FileInputStream(CA_TRUSTSTORE_NAME)) {
			cacerts.load(fis, rootCertPassword);
		}

		var tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(cacerts);

		/*
		 * bind the key and trust stores / managers
		 */

		var sslContext = SSLContext.getInstance("TLSv1.3");
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

		/*
		 * Run the https listener 
		 * Note: Only supports HTTP/1.1, not 2 or later ....
		 */
		server = HttpsServer.create(new InetSocketAddress(HTTPS_PORT), 0);

		server.setHttpsConfigurator (new HttpsConfigurator(sslContext) {
			public void configure (HttpsParameters params) {

				// get the remote address if needed
				InetSocketAddress remote = params.getClientAddress();
				System.out.println("Remote "+remote.getHostString());

				// get the default parameters

				SSLContext sc = getSSLContext();
				SSLParameters sslparams = sc.getDefaultSSLParameters();

				sslparams.setWantClientAuth(true);
				params.setSSLParameters(sslparams);
			}
		});

		server.createContext(URI_RESOURCE, new MyHandler());
		server.setExecutor(null); // creates a default executor
		server.start();

	}

	/**
	 * Handles the requests on URI_RESOURCE
	 * @author Alan R. White
	 */
	class MyHandler implements HttpHandler {
		public void handle(HttpExchange tx) throws IOException {

			System.out.println("Method "+tx.getRequestMethod());
			System.out.println("URI "+tx.getRequestURI());
			tx.getRequestHeaders().forEach((k,v) -> {
				System.out.println("Header: "+k);
				System.out.println("\tValue: "+v);
			});
			System.out.println("Protocol "+tx.getProtocol());

			switch(tx.getRequestMethod()) {

			case "GET" -> {
				var responseBody = "This is the response for an unauthenticated caller";

				if ( tx instanceof HttpsExchange ) {
					var u = (HttpsExchange) tx;
					var s = u.getSSLSession();
					if ( s != null ) {
						try {
							var rp = s.getPeerPrincipal();
							System.out.println("Remote P: "+rp.getName()+" ("+rp.getClass()+")");
							responseBody = "This is the response for "+rp.getName();
							System.out.println("Client ID: "+getCN(s).orElse("Not Found"));

						} catch(SSLPeerUnverifiedException e) {
							System.out.println("Remote P: Not Provided");
						} catch(Exception e) {
							e.printStackTrace();
						}
					} else
						System.out.println("Hmmm SSL Session is null");
				}

				tx.sendResponseHeaders(200, responseBody.length());
				OutputStream os = tx.getResponseBody();
				os.write(responseBody.getBytes());
				os.close();
			}

			default -> {
				var responseBody = "Unsupported Operation";
				tx.sendResponseHeaders(405, responseBody.length());
				OutputStream os = tx.getResponseBody();
				os.write(responseBody.getBytes());
				os.close();
			}
			}
		}
	}

	/**
	 * Connect to the server that presents a custom signed cert and optionally 
	 * provide a client certificate as identity
	 * 
	 * @param uri the URI to contact, e.g. https://localhost:8000/v1/foo
	 * @param caTrustStoreName file name containing root signing cert of cert the server presents
	 * @param clientKeyStore file name containing client certificate and private key
	 * @param clientCertKey name of the entry in the key store containing the client 
	 * certificate and private key
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyManagementException
	 * @throws InterruptedException
	 * @throws UnrecoverableKeyException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 */
	private void makeClientRequest(
			String uri,
			String caTrustStoreName,
			Optional<String> clientKeyStore,
			Optional<String> clientCertKey)
					throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
					IOException, KeyManagementException, InterruptedException, UnrecoverableKeyException, 
					InvalidKeyException, SignatureException, NoSuchProviderException {

		Objects.requireNonNull(uri);
		Objects.requireNonNull(caTrustStoreName);
		
		/*
		 * Prepare any key & cert store the https client may use to identify itself
		 */

		KeyManager[] keyManagers = null;
		
		if ( clientKeyStore.isPresent() ) {
			var passphrase = "passphrase".toCharArray();
			var clientKS = KeyStore.getInstance("pkcs12");

			var getSignedCert = false;
			try (FileInputStream fis = new FileInputStream(CLIENT_KEYSTORE_NAME)) {
				clientKS.load(fis, passphrase);
				if ( !(clientKS.containsAlias(clientCertKey.get())) || !(clientKS.containsAlias(clientCertKey.get())) ) {
					getSignedCert = true;
				}

			} catch (FileNotFoundException e) {
				clientKS.load(null, passphrase);
				getSignedCert = true;
			}

			if ( getSignedCert ) {
				// build pkcs10 csr and get it signed by BasicCA

				var keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(2048);
				var certKeyPair = keyGen.generateKeyPair();

				var csr = new PKCS10(certKeyPair.getPublic());
				var name = new X500Name("CN=localclient,O=arwhite,L=Glasgow,C=GB");
				csr.encodeAndSign(name, certKeyPair.getPrivate(), SignatureUtil.getDefaultSigAlgForKey(certKeyPair.getPrivate()));

				var certChain = ca.issueClientCert(csr);
				clientKS.setKeyEntry(clientCertKey.get(), certKeyPair.getPrivate(), 
						passphrase, certChain);

				try (FileOutputStream fos = new FileOutputStream(clientKeyStore.get())) {
					clientKS.store(fos, passphrase);
				}

			}

			var kmf = KeyManagerFactory.getInstance("PKIX");
			kmf.init(clientKS, passphrase);
			
			keyManagers = kmf.getKeyManagers();
		}

		/*
		 * Ensure this client can trust the certificate that the server presents 
		 */

		KeyStore cacerts = KeyStore.getInstance("pkcs12");
		char[] rootCertPassword = "rootcert".toCharArray();

		try (FileInputStream fis = new FileInputStream(caTrustStoreName)) {
			cacerts.load(fis, rootCertPassword);
		}

		var tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(cacerts);

		/*
		 * Tie together the key and trust managers for the call
		 */

		var sslContext = SSLContext.getInstance("TLSv1.3");
		sslContext.init(keyManagers, tmf.getTrustManagers(), null);

		/*
		 * Make the call
		 */

		var client = HttpClient.newBuilder()
				.sslContext(sslContext)
				.build();

		var request = HttpRequest.newBuilder()
				.uri(URI.create(uri))
				.build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

		printHttpResponse(response);

	}

	/**
	 * DRY pretty print http response
	 * @param response
	 */
	private void printHttpResponse(HttpResponse<String> response) {
		System.out.println("Status:\t"+response.statusCode());
		System.out.println("Request:\t"+response.request());
		System.out.println("Previous:\t"+(response.previousResponse().isPresent() ? response.previousResponse().get() : "none"));
		System.out.println("Headers:\t"+response.headers());
		System.out.println("Body:\t"+response.body());
		System.out.println("URI:\t"+response.uri());
		System.out.println("Version:\t"+response.version());	

		response.sslSession().ifPresent(ssl -> {
			System.out.println("SSL Protocol\t"+ssl.getProtocol());
			System.out.println("SSL Peer ID\t"+getCN(ssl).orElse("Not Found"));
		});
	}

	/**
	 * Verbose way of extracting the CN from a DN - everything SSL related is verbose it seems
	 * 
	 * @param sslSession
	 * @return Optional String populated if the CN is present
	 */
	private Optional<String> getCN(SSLSession sslSession) {
		Optional<String> clientName = Optional.empty();

		try {
			var ln = new LdapName(sslSession.getPeerPrincipal().getName());
			var clientNameOpt = ln.getRdns().stream()
					.filter(rdn -> rdn.getType().equalsIgnoreCase("CN"))
					.findFirst();

			if ( clientNameOpt.isPresent() )
				clientName = Optional.of((String) clientNameOpt.get().getValue());

		} catch(Exception e) {
			e.printStackTrace();
		}

		return clientName;
	}

	/**
	 * Do it
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		/*
		 * Set up the CA, Server etc.
		 */

		var tr = new TestRig();

		/*
		 * Run our server
		 */

		tr.runServer();

		/*
		 * Make one way and two way TLS secured Http requests
		 */

		Thread.sleep(2000);
		tr.makeClientRequest(
				"https://localhost:"+HTTPS_PORT+URI_RESOURCE, 
				CA_TRUSTSTORE_NAME, 
				Optional.empty(), 
				Optional.empty());

		Thread.sleep(2000);
		tr.makeClientRequest(
				"https://localhost:"+HTTPS_PORT+URI_RESOURCE, 
				CA_TRUSTSTORE_NAME, 
				Optional.of(CLIENT_KEYSTORE_NAME), 
				Optional.of(CLIENT_CERT_KEY));

		/*
		 * Wait for a long time while we test the server
		 * 
		 * You can test making a trusted connection by telling curl about the root CA
		 * curl https://localhost:8000/v1/foo/ --cacert /tmp/arw-root-cert.pem
		 */

		Thread.sleep(1000000);
	}

}
