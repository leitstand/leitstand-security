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

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;

import java.security.MessageDigest;

/**
 * Computes a <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function" title="Open secure hash function wikipedia article">secure hashcode</a> from a given byte array or 
 * <code>MAX_RADIX</code> representation of the byte array.
 * <p>
 * The underlying secure hash function depends on the {@link SecureHashes} factory method that was called to create the <code>SecureHashcode</code> instance.
 * </p>
 * The <code>SecureHashcode</code> implementation is not thread-safe and must not be cached. 
 * Obtain a fresh instance for every hash computation.
 */
public class SecureHashFunction {

	private MessageDigest digest;
	
	/**
	 * Create a <code>SecureHashcode</code> implementation.
	 * @param digest - the message digest to compute the hash value
	 */
	SecureHashFunction(MessageDigest digest){
		this.digest = digest;
	}
	
	/**
	 * Computes a hash value for the specified byte array.
	 * @param data - the data to compute the hash from
	 * @return the hash value
	 */
	public byte[] hash(byte[] data){
		return digest.digest(data);
	}
	
	/**
	 * Computes the hash value for the specified text by converting the text to a byte array using UTF-8 character encoding.
	 * @param data - the data to compute the hash from
	 * @return the hash value
	 */
	public byte[] hash(String text) {
		return hash(toUtf8Bytes(text));
	}
	
	/**
	 * Returns the name of the underlying hash algorithm.
	 * @return the name of the underlying hash algorithm.
	 */
	public String getAlgorithm() {
		return digest.getAlgorithm();
	}
	
	/**
	 * Returns the length of the computed hash value in bytes.
	 * @return the length of the computed hash value in bytes.
	 */
	public int getLengthInBytes() {
		return digest.getDigestLength();
	}
	
}
