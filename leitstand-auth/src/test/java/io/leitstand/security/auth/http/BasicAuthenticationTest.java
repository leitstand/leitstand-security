/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static java.util.Base64.getEncoder;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import javax.security.enterprise.credential.Password;

import org.junit.Test;

import io.leitstand.security.auth.UserName;

public class BasicAuthenticationTest {

	
	@Test
	public void accept_null_values() {
		assertNull(BasicAuthentication.valueOf(null));
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void do_not_accept_non_basic_authorization_headers() {
		Authorization header = new Authorization("Bearer XYZ");
		BasicAuthentication.valueOf(header);
	}
	
	@Test
	public void can_decode_basic_authorization_header() {
		Authorization header = new Authorization("Basic "+getEncoder().encodeToString(toUtf8Bytes("user:password")));
		BasicAuthentication auth = new BasicAuthentication(header);
		assertEquals(UserName.valueOf("user"),auth.getUserName());
		assertArrayEquals(new Password("password").getValue(),auth.getPassword().getValue());
	}
	
}
