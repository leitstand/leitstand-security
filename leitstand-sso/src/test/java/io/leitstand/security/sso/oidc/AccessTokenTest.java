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
package io.leitstand.security.sso.oidc;

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static java.util.stream.Collectors.joining;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;

import org.junit.Test;

import io.leitstand.security.auth.jwt.Json;

public class AccessTokenTest {
	
	static String accessToken(Date created, Date expiresIn, String... scopes) {
		
		String scope = Arrays.stream(scopes).collect(joining(" "));
		
		return "{\n" + 
		"  \"jti\": \"3573fd34-4286-49f9-9f40-4fae1abd29ad\",\n" + 
		"  \"exp\": "+expiresIn.getTime()+",\n" + 
		"  \"nbf\": 0,\n" + 
		"  \"iat\": "+created.getTime()+",\n" + 
		"  \"iss\": \"http://localhost:8081/auth/realms/leitstand\",\n" + 
		"  \"sub\": \"6e85a73d-a04a-4a58-adcb-2927a127abd1\",\n" + 
		"  \"typ\": \"Bearer\",\n" + 
		"  \"azp\": \"leitstand\",\n" + 
		"  \"auth_time\": 0,\n" + 
		"  \"session_state\": \"daf7874d-e9d2-498f-967c-c3ebf45429bc\",\n" + 
		"  \"acr\": \"1\",\n" + 
		"  \"scope\": \""+scope+"\"\n" + 
		"}";
	}
	

	@Test
	public void decode_access_token() {
		Date created = new Date();
		Date expires = new Date(created.getTime()+1000);
		String json = accessToken(created,expires,"admin","element","ui");
		AccessToken accessToken = Json.fromJson(AccessToken.class, json);
		assertEquals(asSet("admin","element","ui"),accessToken.getScopes());
		assertFalse(accessToken.isExpired());
		assertEquals("6e85a73d-a04a-4a58-adcb-2927a127abd1",accessToken.getSub());
		assertEquals(created,accessToken.getDateCreated());
		assertEquals(expires,accessToken.getDateExpiry());
	}
	
	@Test
	public void decode_access_token_with_no_scopes() {
		Date created = new Date();
		Date expires = new Date(created.getTime()+1000);
		String json = accessToken(created,expires);
		AccessToken accessToken = Json.fromJson(AccessToken.class, json);
		assertTrue(accessToken.getScopes().isEmpty());
		assertFalse(accessToken.isExpired());
		assertEquals("6e85a73d-a04a-4a58-adcb-2927a127abd1",accessToken.getSub());
		assertEquals(created,accessToken.getDateCreated());
		assertEquals(expires,accessToken.getDateExpiry());
	}
	
	@Test
	public void decode_expired_access_token() {
		Date created = new Date(System.currentTimeMillis() - 2000);
		Date expires = new Date(created.getTime()-1000);
		String json = accessToken(created,expires,"admin","element","ui");
		AccessToken accessToken = Json.fromJson(AccessToken.class, json);
		assertEquals(asSet("admin","element","ui"),accessToken.getScopes());
		assertTrue(accessToken.isExpired());
		assertEquals("6e85a73d-a04a-4a58-adcb-2927a127abd1",accessToken.getSub());
		assertEquals(created,accessToken.getDateCreated());
		assertEquals(expires,accessToken.getDateExpiry());
	}
	
}
