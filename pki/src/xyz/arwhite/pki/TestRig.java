package xyz.arwhite.pki;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManagerFactory;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import sun.security.pkcs10.PKCS10;
import sun.security.util.SignatureUtil;
import sun.security.x509.X500Name;

public class TestRig {

	private static final String CA_TRUSTSTORE_NAME = "/tmp/arw-root-cert.jks";
	private static final String CA_CERT_KEY = "root.pki.arwhite.xyz";

	private static final String SERVER_KEYSTORE_NAME = "/tmp/arw-server.jks";
	private static final String SERVER_CERT_KEY = "active.auth.arwhite.xyz";

	private static final String CLIENT_KEYSTORE_NAME = "/tmp/arw-client.jks";
	private static final String CLIENT_CERT_KEY = "active.auth.arwhite.xyz";

	private static final String URI_RESOURCE = "/v1/foo/";
	private static final int HTTPS_PORT = 8000;

	private BasicCA ca;

	public TestRig() 
			throws InvalidKeyException, UnrecoverableKeyException, KeyStoreException, 
			NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, 
			IOException, InterruptedException, KeyManagementException {

		/*
		 * Set up our CA
		 */
		ca = new BasicCA();

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

		var tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(serverKS);

		var sslContext = SSLContext.getInstance("TLSv1.3");
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

		/*
		 * Run a https listener 
		 * Note: Only supports HTTP/1.1, not 2 or later ....
		 */
		var server = HttpsServer.create(new InetSocketAddress(HTTPS_PORT), 0);

		server.setHttpsConfigurator (new HttpsConfigurator(sslContext) {
			public void configure (HttpsParameters params) {

				// get the remote address if needed
				InetSocketAddress remote = params.getClientAddress();
				System.out.println("Remote "+remote.getHostString());

				SSLContext c = getSSLContext();

				// get the default parameters
				SSLParameters sslparams = c.getDefaultSSLParameters();
				//				if (remote.equals("fred") ) {
				//					// modify the default set for client x
				//				}
				sslparams.setWantClientAuth(true);

				params.setSSLParameters(sslparams);
				// statement above could throw IAE if any params invalid.
				// eg. if app has a UI and parameters supplied by a user.

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
		public void handle(HttpExchange t) throws IOException {

			System.out.println("Method "+t.getRequestMethod());
			System.out.println("URI "+t.getRequestURI());
			t.getRequestHeaders().forEach((k,v) -> {
				System.out.println("Header: "+k);
				System.out.println("\tValue: "+v);
			});
			System.out.println("Protocol "+t.getProtocol());

			var responseBody = "This is the response for an unauthenticated caller";
			if ( t instanceof HttpsExchange ) {
				var u = (HttpsExchange) t;
				var s = u.getSSLSession();
				if ( s != null ) {
					try {
						var rp = s.getPeerPrincipal();
						System.out.println("Remote P: "+rp.getName());
						responseBody = "This is the response for "+rp.getName();
						// System.out.println("Hmmm SSL Session is NOT null");
					} catch(SSLPeerUnverifiedException e) {
						System.out.println("Remote P: Not Provided");
					}
				} else
					System.out.println("Hmmm SSL Session is null");

				// we need to see if a cert was provided
				// and was signed by the CA we trust? ie not an identity provided by some dodgy
				// CA - I mean we could only trust certs from our CA to do the same thing

				// in this example code we do only trust client certs signed by our CA so


			}

			InputStream is = t.getRequestBody();
			var input = new String(is.readAllBytes(), StandardCharsets.UTF_8);
			// var response = "This is the response";
			t.sendResponseHeaders(200, responseBody.length());
			OutputStream os = t.getResponseBody();
			os.write(responseBody.getBytes());
			os.close();
		}
	}

	/**
	 * Connects to the server that presents the custom signed cert
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 * @throws InterruptedException 
	 */
	private void makeOneWayTLSClientRequest() 
			throws KeyStoreException, FileNotFoundException, IOException, 
			NoSuchAlgorithmException, CertificateException, KeyManagementException, InterruptedException {

		KeyStore cacerts = KeyStore.getInstance("pkcs12");
		char[] rootCertPassword = "rootcert".toCharArray();

		try (FileInputStream fis = new FileInputStream(CA_TRUSTSTORE_NAME)) {
			cacerts.load(fis, rootCertPassword);
		}

		var kmf = KeyManagerFactory.getInstance("PKIX");
		var tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(cacerts);

		var sslContext = SSLContext.getInstance("TLSv1.3");
		sslContext.init(null, tmf.getTrustManagers(), null);

		var client = HttpClient.newBuilder()
				.sslContext(sslContext)
				.build();

		var request = HttpRequest.newBuilder()
				.uri(URI.create("https://localhost:"+HTTPS_PORT+URI_RESOURCE))
				.build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());


		System.out.println("Status:\t"+response.statusCode());
		System.out.println("Request:\t"+response.request());
		System.out.println("Previous:\t"+(response.previousResponse().isPresent() ? response.previousResponse().get() : "none"));
		System.out.println("Headers:\t"+response.headers());
		System.out.println("Body:\t"+response.body());
		System.out.println("URI:\t"+response.uri());
		System.out.println("Version:\t"+response.version());	

		response.sslSession().ifPresent(ssl -> {
			System.out.println("SSL Protocol\t"+ssl.getProtocol());
			try {
				System.out.println("SSL Peer ID\t"+ssl.getPeerPrincipal());
			} catch (SSLPeerUnverifiedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		});
	}

	/**
	 * Connect to the server that presents the custom signed cert and authenticates
	 * using a custom client cert.
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	private void makeTwoWayTLSClientRequest() 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

		/*
		 * Prepare key & cert store the https client will use to identify itself
		 */
		var passphrase = "passphrase".toCharArray();
		var clientKS = KeyStore.getInstance("pkcs12");

		var getSignedCert = false;
		try (FileInputStream fis = new FileInputStream(CLIENT_KEYSTORE_NAME)) {
			clientKS.load(fis, passphrase);
			if ( !(clientKS.containsAlias(CLIENT_CERT_KEY)) || !(clientKS.containsAlias(CLIENT_CERT_KEY)) ) {
				getSignedCert = true;
			}

		} catch (FileNotFoundException e) {
			clientKS.load(null, passphrase);
			getSignedCert = true;
		}

		if ( getSignedCert ) {
			// build pkcs10 csr and get it signed by BasicCA



		}

		//		var client = HttpClient.newBuilder()
		//				.sslContext(SSLContext.getDefault())
		//				.sslParameters()
		//				.build();
		//		
		//		
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
		 * Test you can make a trusted connection, by telling curl about the root CA
		 * curl https://localhost:8000/v1/foo/ --cacert /tmp/arw-root-cert.pem
		 */

		Thread.sleep(2000);
		tr.makeOneWayTLSClientRequest();

		/*
		 * Wait for a long time while we test the server
		 */

		Thread.sleep(1000000);
	}

}
