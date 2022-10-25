package xyz.arwhite.pki;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
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

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsParameters;




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
		 * Prepare key & cert store the https listener will use
		 */
		char[] passphrase = "passphrase".toCharArray();
		KeyStore serverKS = KeyStore.getInstance("JKS");

		boolean getSignedCert = false;
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
			// using a manually built jks for now
		}

		serverKS.load(new FileInputStream(SERVER_KEYSTORE_NAME), passphrase);

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(serverKS, passphrase);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(serverKS);

		SSLContext sslContext = SSLContext.getInstance("TLS");
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

				SSLContext c = getSSLContext();

				// get the default parameters
				SSLParameters sslparams = c.getDefaultSSLParameters();
				//				if (remote.equals("fred") ) {
				//					// modify the default set for client x
				//				}
				System.out.println("Remote "+remote.getHostString());

				params.setSSLParameters(sslparams);
				// statement above could throw IAE if any params invalid.
				// eg. if app has a UI and parameters supplied by a user.

			}
		});

		server.createContext(URI_RESOURCE, new MyHandler());
		server.setExecutor(null); // creates a default executor
		server.start();

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
			String response = "This is the response";
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
