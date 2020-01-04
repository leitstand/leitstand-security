/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.mac;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.leitstand.security.crypto.Secret;

/**
 * The {@link MessageAuthenticationCode} factory.
 */
public class MessageAuthenticationCodes {

	private static final String HMACSHA256 = "HmacSHA256";
	private static final Logger LOG = Logger.getLogger(MessageAuthenticationCodes.class.getName());

	/**
	 * Creates a {@link MessageAuthenticationCode} to compute HMAC-SHA256 message authentication codes.
	 * @param secret - the secret to compute the authentication code
	 * @return the initialized {@link MessageAuthenticationCode}
	 */
	public static MessageAuthenticationCode hmacSha256(Secret secret) {
		try{
			Mac hmacSha256 = Mac.getInstance(HMACSHA256);
			hmacSha256.init(new SecretKeySpec(secret.toByteArray(), HMACSHA256));
			return new MessageAuthenticationCode(hmacSha256);
		} catch (Exception e){
			LOG.log(Level.SEVERE, "An error occured while calculating HmacSHA256: "+e.getMessage(), e);
			throw new MessageAuthenticationCodeException(e);
		}
	}
	
	
	private MessageAuthenticationCodes() {
		// No instances allowed.
	}
}
