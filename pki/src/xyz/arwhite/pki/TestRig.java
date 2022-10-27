package xyz.arwhite.pki;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
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
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import sun.security.pkcs10.PKCS10;
import sun.security.util.SignatureUtil;
import sun.security.x509.X500Name;

public class TestRig {

	private static final String SERVER_KEYSTORE_NAME = "/tmp/arw-server.jks";
	private static final String SERVER_CERT_KEY = "active.auth.arwhite.xyz";
	private static final String URI_RESOURCE = "/v1/foo/";
	private static final int HTTPS_PORT = 8000;

	public TestRig() 
			throws InvalidKeyException, UnrecoverableKeyException, KeyStoreException, 
			NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, 
			IOException, InterruptedException, KeyManagementException {

		/*
		 * Set up our CA
		 */
		var ca = new BasicCA();
		
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
				

				params.setSSLParameters(sslparams);
				// statement above could throw IAE if any params invalid.
				// eg. if app has a UI and parameters supplied by a user.

			}
		});

		server.createContext(URI_RESOURCE, new MyHandler());
		server.setExecutor(null); // creates a default executor
		server.start();
		
		/*
		 * Test you can make a trusted connection, by telling curl about the root CA
		 * curl https://localhost:8000/v1/foo/ --cacert root.pki.arwhite.xyz.pem
		 */

		// client needs the root cert to put in a trust store
		// client defines trust store to use
		// make client https call
		// check response
		// celebrate
		// halt server
		
		// exit
		
		
		/*
		 * Wait for a long time while we test the server
		 */
		Thread.sleep(1000000);
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


			InputStream is = t.getRequestBody();
			var input = new String(is.readAllBytes(), StandardCharsets.UTF_8);
			var response = "This is the response";
			t.sendResponseHeaders(200, response.length());
			OutputStream os = t.getResponseBody();
			os.write(response.getBytes());
			os.close();
		}
	}

	/**
	 * Do it
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		new TestRig();

	}

}
