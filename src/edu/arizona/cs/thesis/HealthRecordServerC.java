package edu.arizona.cs.thesis;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.GregorianCalendar;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpEntity;
import org.apache.http.entity.InputStreamEntity;

import edu.arizona.jbv.thesis.crypto.AES256Encryptor;
import edu.arizona.jbv.thesis.crypto.CMSSignedDataEncryptor;
import edu.arizona.jbv.thesis.crypto.Encryptor;
import edu.arizona.jbv.thesis.data.IdentityToken;

/**
 * The health record servers hold the confidential records of the people. The
 * are accessible over plain Http (not Https) because unknown clients may need
 * to contact them. However, there is still security in the form of encryption
 * and signatures from the TrustServer.
 * 
 * There should not be 3 servlets to handle this, but in the prototype, this
 * made the logistics easier to manage.
 * 
 * @author Jorge Vergara
 * 
 */
public class HealthRecordServerC extends HttpServlet {

	/**
	 * Version 1. 4/24/2013
	 */
	private static final long serialVersionUID = 1L;

	public static final String pathToCertsFolder = "/cs/cgi/projects/mhealth/tomcat/DevMobileTracker/webapps/MobileTracker/certs/";

	/**
	 * This is not over SSL. However, it is AES encrypted with a symmetric key.
	 * Currently it is not a strong key, but it is encrypted. After decryption,
	 * the identity token signature is checked, and if it is trusted (that is,
	 * if it was signed by the TrustServer), then the health records are
	 * returned in encrypted form.
	 */
	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		try {
			HttpEntity ent = new InputStreamEntity(request.getInputStream(),
					request.getContentLength());
			ObjectInputStream ois = new ObjectInputStream(ent.getContent());
			Object encryptedEncodedCMSData = ois.readObject();

			// if the health record server cannot be trusted with these
			// credentials, a check could go out to the trust server instead, to
			// confirm validity
			Encryptor enc = new CMSSignedDataEncryptor(pathToCertsFolder
					+ "TrustServerC.jks", pathToCertsFolder
					+ "TrustServerC.key");
			Encryptor aesEnc = new AES256Encryptor();
			Object step1 = aesEnc.byteToObject(aesEnc
					.decrypt(encryptedEncodedCMSData));
			Object step2 = enc.decrypt(step1);
			IdentityToken token = (IdentityToken) enc
					.byteToObject((byte[]) step2);

			if (!isExpired(token)) {
				ObjectOutputStream oos = new ObjectOutputStream(
						response.getOutputStream());
				oos.writeObject(aesEnc
						.encrypt("THESE ARE THE TOP SECRET FILES FROM HEALTH SERVER C!"));
			} else {
				response.getWriter().write("INVALID TOKEN!!!");
			}

		} catch (Exception e) {
			e.printStackTrace();
			e.printStackTrace(response.getWriter());
		}

	}

	private boolean isExpired(IdentityToken token) {
		if (token.expiration.compareTo(new GregorianCalendar()) < 0)
			return false;
		return false;
	}
}
