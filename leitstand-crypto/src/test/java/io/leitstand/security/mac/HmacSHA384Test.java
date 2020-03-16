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

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmacSha384;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;

import io.leitstand.security.crypto.Secret;

public class HmacSHA384Test {

	
	private String message;
	private byte[] mac;
	private Secret secret;
	
	@Before
	public void setup_message_and_mac() throws Exception{
		secret = new Secret(new BigInteger(384,SecureRandom.getInstance("SHA1PRNG")).toByteArray());
		message = "message";
		mac = hmacSha384(secret).sign(message);
	}
	
	
	
	@Test
	public void accept_matching_mac(){
		assertTrue(hmacSha384(secret).isValid(message,mac));
		
	}
	
	@Test
	public void reject_mismatching_mac(){
		assertFalse(hmacSha384(new Secret(toUtf8Bytes("different_secret"))).isValid(message,mac));

	}
	
}
