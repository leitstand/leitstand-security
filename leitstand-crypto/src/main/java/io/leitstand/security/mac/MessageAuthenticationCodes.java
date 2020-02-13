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
package io.leitstand.security.mac;

import static java.util.logging.Level.SEVERE;

import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.leitstand.security.crypto.Secret;

/**
 * The {@link MessageAuthenticationCode} factory.
 */
public class MessageAuthenticationCodes {

	private static final String HMACSHA256 = "HmacSHA256";
	private static final String HMACSHA384 = "HmacSHA384";
	private static final String HMACSHA512 = "HmacSHA512";
	private static final Logger LOG = Logger.getLogger(MessageAuthenticationCodes.class.getName());

	public static MessageAuthenticationCode hmac(String alg, Secret secret) {
		try{
			Mac hmac = Mac.getInstance(alg);
			hmac.init(new SecretKeySpec(secret.toByteArray(), alg));
			return new MessageAuthenticationCode(hmac);
		} catch (Exception e){
			LOG.log(SEVERE, "An error occured while calculating HmacSHA256: "+e.getMessage(), e);
			throw new MessageAuthenticationCodeException(e);
		}
	}
	
	public static MessageAuthenticationCode hmac(SecretKeySpec secret) {
		try{
			Mac hmac = Mac.getInstance(secret.getAlgorithm());
			hmac.init(secret);
			return new MessageAuthenticationCode(hmac);
		} catch (Exception e){
			LOG.log(SEVERE, "An error occured while calculating HmacSHA256: "+e.getMessage(), e);
			throw new MessageAuthenticationCodeException(e);
		}
	}
	
	/**
	 * Creates a {@link MessageAuthenticationCode} to compute HMAC-SHA256 message authentication codes.
	 * @param secret - the secret to compute the authentication code
	 * @return the initialized {@link MessageAuthenticationCode}
	 */
	public static MessageAuthenticationCode hmacSha256(Secret secret) {
		return hmac(HMACSHA256,secret);
	}
	
	/**
	 * Creates a {@link MessageAuthenticationCode} to compute HMAC-SHA384 message authentication codes.
	 * @param secret - the secret to compute the authentication code
	 * @return the initialized {@link MessageAuthenticationCode}
	 */
	public static MessageAuthenticationCode hmacSha384(Secret secret) {
		return hmac(HMACSHA384,secret);
	}
	
	/**
	 * Creates a {@link MessageAuthenticationCode} to compute HMAC-SHA512 message authentication codes.
	 * @param secret - the secret to compute the authentication code
	 * @return the initialized {@link MessageAuthenticationCode}
	 */
	public static MessageAuthenticationCode hmacSha512(Secret secret) {
		return hmac(HMACSHA512,secret);
	}
	
	
	
	private MessageAuthenticationCodes() {
		// No instances allowed.
	}
}
