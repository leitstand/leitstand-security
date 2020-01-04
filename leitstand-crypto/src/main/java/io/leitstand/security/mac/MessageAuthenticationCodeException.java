/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.mac;


/**
 * The <code>MessageAuthenticationCodeException</code> is thrown whenever a problem occurred while computing a message authentication code.
 */
public class MessageAuthenticationCodeException extends RuntimeException {
 	
	private static final long serialVersionUID = 1L;

	/**
	 * Create a <code>MessageAuthenticationCodeException</code>.
	 * @param cause - the root cause
	 */
	public MessageAuthenticationCodeException(Exception cause) {
		super(cause);
	}
}
