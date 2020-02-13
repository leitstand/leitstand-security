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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

import java.util.Properties;
import java.util.function.Supplier;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.etc.Environment;
import io.leitstand.commons.etc.FileProcessor;
import io.leitstand.security.auth.http.LoginConfigurationProvider;
import io.leitstand.security.crypto.MasterSecret;

@RunWith(MockitoJUnitRunner.class)
public class OidcConfigProviderTest {
	
	private static final String AUTHORIZATION_ENDPOINT = "http://localhost/authorize";
	private static final String TOKEN_ENDPOINT = "http://localhost/token";
	private static final String USER_ENDPOINT = "http://localhost/userinfo";
	private static final String CLIENT_SECRET = "secret";
	private static final String CLIENT_ID = "id";
	
	@Mock
	private Environment env;
	
	@Mock
	private MasterSecret masterSecret;
	
	@Mock
	private LoginConfigurationProvider loginConfigProvider;
	
	@InjectMocks
	private OidcConfigProvider provider = new OidcConfigProvider();
	
	@Test
	public void openid_config_is_null_when_oidc_properties_are_incomplete() {
		when(env.loadConfig(eq("sso.properties"),any(FileProcessor.class),any(Supplier.class))).thenCallRealMethod();
		provider.onStartup();

		
		assertNull(provider.getOpenIdConfig());
	}
	
	@Test
	@Ignore
	public void read_openid_config_with_default_timeouts() {
		Properties openIdProperties = new Properties();
		openIdProperties.put("OIDC_AUTHORIZATION_ENDPOINT",AUTHORIZATION_ENDPOINT);
		openIdProperties.put("OIDC_TOKEN_ENDPOINT",TOKEN_ENDPOINT);
		openIdProperties.put("OIDC_USERINFO_ENDPOINT", USER_ENDPOINT);
		openIdProperties.put("OIDC_CLIENT_ID",CLIENT_ID);
		openIdProperties.put("OIDC_CLIENT_SECRET",CLIENT_SECRET);
		when(env.loadConfig(eq("sso.properties"),any(FileProcessor.class),any(Supplier.class))).thenReturn(openIdProperties);
		
		provider.onStartup();
		OidcConfig config = provider.getOpenIdConfig();
		
		assertNotNull(config);
		assertEquals(AUTHORIZATION_ENDPOINT,config.getAuthorizationEndpoint().toString());
		assertEquals(TOKEN_ENDPOINT,config.getTokenEndpoint().toString());
		assertEquals(USER_ENDPOINT,config.getUserInfoEndpoint().toString());
		assertEquals(CLIENT_ID,config.getClientId().toString());
		assertThat(config.getClientSecret().compareTo(CLIENT_SECRET),is(true));
		assertEquals(10000,config.getConnectTimeout());
		assertEquals(10000,config.getReadTimeout());
		
	}
	
	@Test
	@Ignore
	public void read_openid_config_with_custom_timeouts() {
		Properties openIdProperties = new Properties();
		openIdProperties.put("OIDC_AUTHORIZATION_ENDPOINT",AUTHORIZATION_ENDPOINT);
		openIdProperties.put("OIDC_TOKEN_ENDPOINT",TOKEN_ENDPOINT);
		openIdProperties.put("OIDC_USERINFO_ENDPOINT", USER_ENDPOINT);
		openIdProperties.put("OIDC_CLIENT_ID",CLIENT_ID);
		openIdProperties.put("OIDC_CLIENT_SECRET",CLIENT_SECRET);
		openIdProperties.put("OIDC_READ_TIMEOUT","1234");
		openIdProperties.put("OIDC_CONNECT_TIMEOUT","5678");
		openIdProperties.put("OIDC_PUBLIC_KEY","bar");
		when(env.loadConfig(eq("sso.properties"),any(FileProcessor.class),any(Supplier.class))).thenReturn(openIdProperties);
		
		provider.onStartup();
		OidcConfig config = provider.getOpenIdConfig();
		
		assertNotNull(config);
		assertEquals(AUTHORIZATION_ENDPOINT,config.getAuthorizationEndpoint().toString());
		assertEquals(TOKEN_ENDPOINT,config.getTokenEndpoint().toString());
		assertEquals(USER_ENDPOINT,config.getUserInfoEndpoint().toString());
		assertEquals(CLIENT_ID,config.getClientId().toString());
		assertThat(config.getClientSecret().compareTo(CLIENT_SECRET),is(true));
		assertEquals(5678,config.getConnectTimeout());
		assertEquals(1234,config.getReadTimeout());
		

	}
	

	
	
}
