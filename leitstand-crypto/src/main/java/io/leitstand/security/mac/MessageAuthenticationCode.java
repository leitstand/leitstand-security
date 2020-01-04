/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.mac;

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;

import java.util.Arrays;

import javax.crypto.Mac;

/**
 * A utility to sign a message by computing a message authentication code or
 * to validate a given MAC of a certain message.
 * <p>
 * The <code>MessageAuthenticationCode</code> is not thread-safe.
 * Use {@link MessageAuthenticationCodes} to create <code>MessageAuthenticationCode</code> instances on demand.
 */
public class MessageAuthenticationCode {

	private Mac mac;
	
	/**
	 * Create a <code>MessageAuthenticationCode</code>.
	 * @param mac - the underlying MAC to do the actual computations
	 */
	MessageAuthenticationCode(Mac mac){
		this.mac = mac;
	}
	
	/**
	 * Verifies a given message authentication code.
	 * @param message - the original message
	 * @param mac - the message authentication code.
	 * @return <code>true</code> if the given MAC is valid, i.e. equal to the computed MAC and 
	 * <code>false</code> otherwise.
	 */
	public boolean isValid(byte[] message, byte[] mac) {
		return Arrays.equals(mac, sign(message));
	}
	
	/**
	 * Verifies a given message authentication code.
	 * @param message - the original message
	 * @param mac - the message authentication code.
	 * @return <code>true</code> if the given MAC is valid, i.e. equal to the computed MAC and 
	 * <code>false</code> otherwise.
	 */
	public boolean isValid(String message, byte[] mac) {
		return isValid(toUtf8Bytes(message),mac);
	}

	/**
	 * Computes the message authentication code for a given message.
	 * @param message - the message text
	 * @return the message authentication code
	 */
	public byte[] sign(String message) {
		return sign(toUtf8Bytes(message));
	}
	
	/**
	 * Computes the message authentication code for a given message.
	 * @param message - the message in bytes
	 * @return the message authentication code
	 */
	public byte[] sign(byte[] message) {
		return mac.doFinal(message);
	}
	
	/**
	 * Returns the MAC algorithm name.
	 * @return the MAC algorithm name.
	 */
	public String getAlgorithm() {
		return mac.getAlgorithm();
	}
	
}
