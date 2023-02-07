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
package io.leitstand.security.sso.oauth2.model;

import static java.lang.System.currentTimeMillis;
import static java.util.UUID.randomUUID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Date;

import javax.persistence.EntityManager;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import io.leitstand.commons.etc.Environment;
import io.leitstand.commons.model.Repository;
import io.leitstand.security.crypto.MasterSecret;
import io.leitstand.security.sso.oidc.oauth2.DefaultRefreshTokenStore;

public class DefaultRefreshTokenStoreIT extends Oauth2IT{

	@Rule
	public TemporaryFolder etc = new TemporaryFolder();
	
	private DefaultRefreshTokenStore store;
	
	@Before
	public void initTestEnvironment() {
		EntityManager em = super.getEntityManager();
		Repository repository = new Repository(em);
		Environment env = new Environment(etc.getRoot());
		MasterSecret secret = new MasterSecret(env);
		secret.init();
		store = new DefaultRefreshTokenStore(repository, secret);
		
	}
	
	
	
	@Test
	public void store_new_refresh_token() {
		String sub = randomUUID().toString();
		String token = "token";
		Date expiry = new Date(currentTimeMillis()+10000);
		transaction(() -> {
			store.storeRefreshToken(sub, token, expiry);
		});
		transaction(() -> {
			assertEquals(token,store.getRefreshToken(sub));
		});
	}
	
	@Test
	public void update_existing_refresh_token() {
		String sub = randomUUID().toString();
		String token = "a";
		Date expiry = new Date(currentTimeMillis()+10000);
		transaction(() -> {
			store.storeRefreshToken(sub, token, expiry);
		});
		transaction(() -> {
			assertEquals(token,store.getRefreshToken(sub));
		});
		String newToken = "b";
		transaction(() -> {
			store.storeRefreshToken(sub, newToken, expiry);
		});
		transaction(() -> {
			assertEquals(newToken,store.getRefreshToken(sub));
		});
	}
	
	@Test
	public void refresh_token_does_not_exist() {
		transaction(() -> {
			String sub = randomUUID().toString();
			assertNull(store.getRefreshToken(sub));
		});
	}
	
	@Test
	public void read_refresh_token() {
		String sub = randomUUID().toString();
		String token = "token";
		Date expiry = new Date(currentTimeMillis()+10000);
		transaction(() -> {
			store.storeRefreshToken(sub, token, expiry);
		});
		transaction(() -> {
			assertEquals(token,store.getRefreshToken(sub));
		});
	}
	
}
