/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.crypto;

import java.security.MessageDigest;

/**
 * A factory for {@link SecureHashFunction} instances.
 */
public final class SecureHashes {
	
	/**
	 * Creates a function to compute MD5 hashes.
	 * @return a function to compute MD5 hashes.
	 */
	public static SecureHashFunction md5(){
		return new SecureHashFunction(createMessageDigest("MD5"));
	}
	
	/**
	 * Creates a function to compute SHA-1 hashes.
	 * @return a function to compute SHA-1 hashes.
	 */
	public static SecureHashFunction sha1() {
		return new SecureHashFunction(createMessageDigest("SHA-1"));
	}
	 
	/**
	 * Creates a function to compute SHA-256 hashes.
	 * @return a function to compute SHA-256 hashes.
	 */
	public static SecureHashFunction sha256(){
		return new SecureHashFunction(createMessageDigest("SHA-256"));
	}


	private static MessageDigest createMessageDigest(String algorithm) {
		try{
			return MessageDigest.getInstance(algorithm);
		} catch( Exception e){
			throw new IllegalArgumentException(e);
		}
	}
	
	
	private SecureHashes(){
		// No instances allowed
	}
}
