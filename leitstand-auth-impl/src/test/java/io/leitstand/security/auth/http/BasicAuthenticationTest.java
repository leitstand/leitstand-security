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
