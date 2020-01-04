/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.mac;

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmacSha256;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;

import io.leitstand.security.crypto.Secret;

public class HmacSHA256Test {

	
	private String message;
	private byte[] mac;
	private Secret secret;
	
	@Before
	public void setup_message_and_mac() throws Exception{
		secret = new Secret(new BigInteger(512,SecureRandom.getInstance("SHA1PRNG")).toByteArray());
		message = "message";
		mac = hmacSha256(secret).sign(message);
	}
	
	
	
	@Test
	public void accept_message_with_correct_mac(){
		assertTrue(hmacSha256(secret).isValid(message,mac));
		
	}
	
	@Test
	public void discard_message_with_incorrect_mac(){
		assertFalse(hmacSha256(new Secret(toUtf8Bytes("different_secret"))).isValid(message,mac));

	}
	
}
