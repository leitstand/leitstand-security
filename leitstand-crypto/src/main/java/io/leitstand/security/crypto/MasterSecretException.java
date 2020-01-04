/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.crypto;


/**
 * The <code>MasterSecretException</code> is thrown by the {@link MasterSecret} to report issues with data encryption or decryption.
 */
public class MasterSecretException extends RuntimeException{

	private static final long serialVersionUID = 1L;

	/**
	 * Create a <code>MasterSecretException</code>.
	 * @param cause - the root cause
	 */
	public MasterSecretException(Exception cause) {
		super(cause);
	}
	
}