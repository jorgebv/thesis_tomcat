package edu.arizona.cs.thesis;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;

import edu.arizona.jbv.thesis.crypto.CMSSignedDataEncryptor;
import edu.arizona.jbv.thesis.crypto.Encryptor;
import edu.arizona.jbv.thesis.data.IdentityToken;
import edu.arizona.jbv.thesis.networking.SSLClient;

/**
 * This servlet is responsible for distributing identity tokens to clients that
 * it trusts. Each trust server should be aware of which patients' health
 * records is available to it, so that it is able to accurately answer trust
 * requests. A trust server may manage trust for multiple health record servers
 * (for example, one trust server for a city).
 * 
 * If a trust server receives a request for a patient that it cannot grant, it
 * should contact another trust server to obtain the token. The connections to
 * other trust servers use SSL, meaning that each trust server will only respond
 * to trust servers and clients that it trusts already. For now, each trust
 * server will follow a fixed route. In the future, a routing algorithm should
 * be implemented to allow for discovery of unknown health records.
 * 
 * The three servlets are not very different in terms of code and should really
 * only be one servlet. They are only 3 servlets for logistic reasons.
 * 
 * @author Jorge Vergara
 * 
 */
public class TrustServerC extends HttpServlet {

	/**
	 * Version 1. 4/24/2013
	 */
	private static final long serialVersionUID = 1L;

	public static final String pathToCertsFolder = "/cs/cgi/projects/mhealth/tomcat/DevMobileTracker/webapps/MobileTracker/certs/";
	public static final int tokenDurationInHours = 3;

	/**
	 * This is over SSL due to the Tomcat config files. Since the user is
	 * trusted at this point, the identity token should be found and delivered.
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		Object twoByteArrays = findUserAndGetIdentityToken(request);
		try {

			ObjectOutputStream oos = new ObjectOutputStream(
					response.getOutputStream());
			oos.writeObject(twoByteArrays);
		} catch (Exception e) {
			e.printStackTrace(response.getWriter());
		}
	}

	/**
	 * Angela and Rosendo are under the jurisdiction of trust server A. Daniel
	 * and Marilyn are under the jurisdiction of trust server B. Nathan and
	 * Terry are under the jurisdiction of trust server C.
	 * 
	 * In the future, the userID would be something other than a non-unique
	 * name, and the check would be more involved than a string comparison. Each
	 * trust server would likely have a database of names or something
	 * equivalent that is not dependant on recompiling the servlet.
	 * 
	 * This method does not deal with finding users that are out of its
	 * jurisdiction -- it simply returns false in that case
	 * 
	 * @param userID
	 * @return Whether the userID is in this trust server's jurisdiction
	 */
	private boolean userUnderJurisdiction(String userID) {
		if ((userID.equals("Nathan") || userID.equals("Terry")))
			return true;
		return false;
	}

	private IdentityToken constructToken(HttpServletRequest request,
			String userID) {

		byte[] clientPublicKey = null;
		byte[] healthRecordServerPublicKey = null;

		Object o = request
				.getAttribute("javax.servlet.request.X509Certificate");
		if (o != null) {
			X509Certificate certs[] = (X509Certificate[]) o;
			X509Certificate cert = certs[0];
			PublicKey k = cert.getPublicKey();
			clientPublicKey = k.getEncoded();

			X509Certificate hrsA = null;
			InputStream inStream = null;
			try {
				inStream = new FileInputStream(pathToCertsFolder
						+ "HealthRecordServerC.crt");
				CertificateFactory cf = CertificateFactory.getInstance("X.509",
						"JC");
				hrsA = (X509Certificate) cf.generateCertificate(inStream);
				healthRecordServerPublicKey = hrsA.getPublicKey().getEncoded();
				inStream.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return new IdentityToken(userID, clientPublicKey,
				healthRecordServerPublicKey, tokenDurationInHours,
				"http://dmft.cs.arizona.edu:8081/MobileTracker/Thesis/HealthRecordServerC");
	}

	/**
	 * This method obtains a token for the specified user. If the user is under
	 * the jurisdiction of this server, this is all done locally, (likely) using
	 * database lookups to find exactly which health record server the userID
	 * belongs to. In this prototype, there is no database and this information
	 * is hardcoded in the constructToken method. There is only 1 health record
	 * server under the jurisdiction of this trust server.
	 * 
	 * If the user is not under the jurisdiction, the trust server should seek
	 * out the appropriate trust server and request the token from it. Because
	 * trust servers will only give tokens to agents that it trusts, some chain
	 * of trust must exist between this trust server and the ultimate permission
	 * granting trust server, or it will not be found. This should use something
	 * similar to a routing algorithm to try and locate the appropriate trust
	 * server and which path to take to get there.
	 * 
	 * In this prototype, it is assumed that trust server A has a relationship
	 * with server B. B has a relationship with both A and C. C only has a
	 * relationship with B. Information about which userIDs each trust server is
	 * willing to distribute tokens for is also assumed to be known.
	 * 
	 * @param userID
	 * @param underJurisdiction
	 * @return The signed and hashed identity token, using the certificate of
	 *         whichever server was willing to distribute the token. The
	 *         CMSSignedData can be reconstructed using these arrays, and the
	 *         token extracted from that.
	 */
	@SuppressWarnings("unchecked")
	public List<byte[]> findUserAndGetIdentityToken(HttpServletRequest request) {
		String userID = request.getParameter("userID");

		if (userUnderJurisdiction(userID)) {
			IdentityToken t = constructToken(request, userID);
			Encryptor enc = new CMSSignedDataEncryptor(pathToCertsFolder
					+ "TrustServerC.jks", pathToCertsFolder
					+ "TrustServerC.key");
			return (List<byte[]>) enc.encrypt(t);
		} else {
			return findUser(userID);
		}
	}

	/**
	 * This method should find the appropriate trust server willing to
	 * distribute a token for the specified user and return the encoded
	 * IdentityToken that it returns. (Encoded IdentityTokens are a
	 * List<byte[]>, use the decryptor class to decrypt them)
	 * 
	 * @param userID
	 * @return The encoded IdentityToken
	 */
	@SuppressWarnings("unchecked")
	private List<byte[]> findUser(String userID) {
		try {
			InputStream truststore = new FileInputStream(new File(
					pathToCertsFolder + "TrustServerCTrust.jks"));
			InputStream clientstore = new FileInputStream(new File(
					pathToCertsFolder + "TrustServerC.jks"));

			SSLClient cli = new SSLClient(truststore, clientstore);
			List<NameValuePair> postParameters = new ArrayList<NameValuePair>();
			postParameters.add(new BasicNameValuePair("userID", userID));
			String paramString = URLEncodedUtils
					.format(postParameters, "utf-8");
			HttpGet post = new HttpGet(
					"https://dmft.cs.arizona.edu:8082/MobileTracker/Thesis/SSL/TrustServerB"
							+ "?" + paramString);
			HttpResponse resp = cli.execute(post);
			InputStream is = resp.getEntity().getContent();
			ObjectInputStream ois = new ObjectInputStream(is);
			Object encodedCMSData = ois.readObject();
			return (List<byte[]>) encodedCMSData;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
