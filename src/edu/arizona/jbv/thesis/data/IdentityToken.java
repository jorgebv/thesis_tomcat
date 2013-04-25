package edu.arizona.jbv.thesis.data;

import java.io.Serializable;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * The name IdentityToken is a bit of a misnomer, as this class ended up
 * containing some of the actual message data as well. The data should be
 * removed and separated, or the class renamed, but the end result is the same.
 * 
 * The IdentityToken class has a short lifespan and identifies that a user was
 * trusted by some trust server. Typically this is the obejct that is signed and
 * presented to the health record server to prove identity.
 * 
 * @author Jorge Vergara
 * 
 */
public class IdentityToken implements Serializable {

	/**
	 * First version 4/26/2013
	 */
	private static final long serialVersionUID = 1L;

	// these keys are not currently used (and may not even be present in Tokens
	// sent from servers, but are still included for future works
	public final byte[] clientPublicKey;
	public final byte[] healthRecordServerPublicKey;

	public final GregorianCalendar expiration;
	public final String userID;
	public final String urlOfHealthRecordServer;

	/**
	 * IdentityToken constructor
	 * 
	 * @param userID
	 *            userID that was queried that led to the creation of this token
	 * @param clientPublicKey
	 *            The public key of the client that requested the token
	 * @param healthRecordServerPublicKey
	 *            The public key of the health record server responsible for the
	 *            userID requested
	 * @param hourDuration
	 *            How many hours this token is valid for
	 * @param urlOfHealthRecordServer
	 *            The url of the health record server responsible for the
	 *            queried user ID
	 */
	public IdentityToken(String userID, byte[] clientPublicKey,
			byte[] healthRecordServerPublicKey, int hourDuration,
			String urlOfHealthRecordServer) {
		this.clientPublicKey = clientPublicKey;
		this.healthRecordServerPublicKey = healthRecordServerPublicKey;
		GregorianCalendar exp = new GregorianCalendar();
		exp.add(Calendar.HOUR, hourDuration);
		expiration = exp;
		this.userID = userID;
		this.urlOfHealthRecordServer = urlOfHealthRecordServer;
	}
}
