package edu.arizona.jbv.thesis.networking;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnManagerParams;
import org.apache.http.conn.params.ConnPerRoute;
import org.apache.http.conn.params.ConnPerRouteBean;
import org.apache.http.conn.scheme.HostNameResolver;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;

/**
 * Instantiating an SSLClient sets up an HttpClient capable of 2 way SSL.
 * 
 * Previous versions of the SSLClient also were successful with 1 way SSL
 * connections, but this has not been tested recently.
 * 
 * The SSLClient passes all requests to this 2 way SSL capable HttpClient, so it
 * is capable of everything the HttpClient is. However, only a few methods are
 * visible from this facade.
 * 
 * Based on:
 * http://stackoverflow.com/questions/4064810/using-client-server-certificates
 * -for-two-way-authentication-ssl-socket-on-androi
 * 
 * @author Jorge Vergara
 * 
 */
@SuppressWarnings("deprecation")
public class SSLClient {

	private DefaultHttpClient sClient;

	/**
	 * 
	 * Constructs an SSLClient
	 * 
	 * @param truststore
	 *            Stream corresponding to the .jks type store of trusted
	 *            certificates
	 * @param clientstore
	 *            Stream corresponding to the .jks type store containing this
	 *            client's certificate
	 */
	public SSLClient(InputStream truststore, InputStream clientstore) {
		try {
			// load truststore certificate
			InputStream clientTruststoreIs = truststore;
			KeyStore trustStore = null;
			trustStore = KeyStore.getInstance("JKS");
			trustStore.load(clientTruststoreIs, "111111".toCharArray());

			// initialize trust manager factory with the read truststore
			TrustManagerFactory trustManagerFactory = null;
			trustManagerFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init(trustStore);

			// setup client certificate

			// load client certificate
			InputStream keyStoreStream = clientstore;
			KeyStore keyStore = null;
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(keyStoreStream, "111111".toCharArray());

			// initialize key manager factory with the read client certificate
			KeyManagerFactory keyManagerFactory = null;
			keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory
					.getDefaultAlgorithm());
			keyManagerFactory.init(keyStore, "111111".toCharArray());

			// initialize SSLSocketFactory to use the certificates
			SSLSocketFactory socketFactory = null;
			socketFactory = new org.apache.http.conn.ssl.SSLSocketFactory(
					SSLSocketFactory.TLS, keyStore, "111111", trustStore,
					(SecureRandom) null, (HostNameResolver) null);

			// Set basic data
			HttpParams params = new BasicHttpParams();
			HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
			HttpProtocolParams.setContentCharset(params, "UTF-8");
			HttpProtocolParams.setUseExpectContinue(params, true);
			HttpProtocolParams.setUserAgent(params, "Android app/1.0.0");

			// Make pool
			ConnPerRoute connPerRoute = new ConnPerRouteBean(12);
			ConnManagerParams.setMaxConnectionsPerRoute(params, connPerRoute);
			ConnManagerParams.setMaxTotalConnections(params, 20);

			// Set timeout
			HttpConnectionParams.setStaleCheckingEnabled(params, false);
			HttpConnectionParams.setConnectionTimeout(params, 20 * 1000);
			HttpConnectionParams.setSoTimeout(params, 20 * 1000);
			HttpConnectionParams.setSocketBufferSize(params, 8192);

			// Some client params
			HttpClientParams.setRedirecting(params, false);

			// Register http/s shemas!
			SchemeRegistry schReg = new SchemeRegistry();
			schReg.register(new Scheme("https", socketFactory, 8082));
			ClientConnectionManager conMgr = new ThreadSafeClientConnManager(
					params, schReg);
			sClient = new DefaultHttpClient(conMgr, params);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Forwards the HttpPost/Get (or whatever else you put in here) to the
	 * HttpClient
	 * 
	 * @param get
	 *            The request to execute
	 * @return The HttpResponse returned by the server
	 * @throws ClientProtocolException
	 * @throws IOException
	 */
	public HttpResponse execute(HttpRequestBase get)
			throws ClientProtocolException, IOException {
		return sClient.execute(get);
	}

}