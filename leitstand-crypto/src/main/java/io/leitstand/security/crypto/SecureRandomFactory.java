/*
 * Copyright 2020 RtBrick Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
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
