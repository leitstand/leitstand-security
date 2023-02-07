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

	/**
	 * Creates a function to compute SHA-512 hashes.
	 * @return a function to compute SHA-512 hashes.
	 */
	public static SecureHashFunction sha512(){
		return new SecureHashFunction(createMessageDigest("SHA-512"));
	}

	   /**
     * Creates a function to compute SHA3-256 hashes.
     * @return a function to compute SHA3-256 hashes.
     */
    public static SecureHashFunction sha3_256(){
        return new SecureHashFunction(createMessageDigest("SHA3-256"));
    }

    /**
     * Creates a function to compute SHA3-512 hashes.
     * @return a function to compute SHA3-512 hashes.
     */
    public static SecureHashFunction sha3_512(){
        return new SecureHashFunction(createMessageDigest("3-512"));
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
