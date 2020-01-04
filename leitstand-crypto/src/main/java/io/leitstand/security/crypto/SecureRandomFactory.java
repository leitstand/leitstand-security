/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * The <code>SecureRandomFactory</code> creates a native, 
 * non-blocking pseudo random number generator (PRNG) using
 * a 440 bits seed as recommended by NIST.
 *
 */
public final class SecureRandomFactory {
	
	/**
	 * Returns a new non-blocking SHA1PRNG pseudo random number generator initialized with a 440bit random seed
	 * as recommended by NIST.
	 * @return an initialized SHA1PRNG.
	 */
	public static SecureRandom newSHA1PRNG(){
		try{
			// Generate 440 bits seed as recommended by NIST
			SecureRandom seedGenerator = SecureRandom.getInstance("NativePRNGNonBlocking","SUN");
			byte[] seed = new byte[55];
			seedGenerator.nextBytes(seed);
			
			SecureRandom sha1prng = SecureRandom.getInstance("SHA1PRNG","SUN");
			sha1prng.setSeed(seed);
			return sha1prng;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e){
			throw new IllegalStateException(e);
		}
	}
	
	private SecureRandomFactory(){
		// No instances allowed
	}
	
}
