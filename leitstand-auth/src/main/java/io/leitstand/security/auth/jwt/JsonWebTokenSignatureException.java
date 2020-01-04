/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jwt;

public class JsonWebTokenSignatureException extends RuntimeException{

	private static final long serialVersionUID = 1L;

	public JsonWebTokenSignatureException(String message) {
		super(message);
	}
	
	public JsonWebTokenSignatureException(Exception cause) {
		super(cause);
	}
	
	
}
