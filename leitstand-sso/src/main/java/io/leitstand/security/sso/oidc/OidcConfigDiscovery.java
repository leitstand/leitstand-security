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

import static io.leitstand.security.auth.http.BasicAuthentication.basicAuthentication;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static javax.ws.rs.client.ClientBuilder.newBuilder;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.Key;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.security.enterprise.credential.Password;
import javax.ws.rs.client.Client;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;
import io.leitstand.commons.jsonb.JsonbDefaults;
import io.leitstand.security.auth.UserName;

public class OidcConfigDiscovery {

	private static final Logger LOG = Logger.getLogger(OidcConfigDiscovery.class.getName());
		
	private URI configEndpoint;
	private long readTimeout;
	private long connectTimeout;
	private UserName clientId;
	private Password clientSecret;
	private String authorizationEndpoint;
	private String userInfoEndpoint;
	private String tokenEndpoint;
	private SigningKeyResolver keyResolver;
	
	
	OidcConfigDiscovery(URI configEndpoint){
		this.configEndpoint = configEndpoint;
		this.readTimeout = 10000;
		this.connectTimeout = 1000;
	}
	
	OidcConfigDiscovery readTimeout(long readTimeout) {
		this.readTimeout = readTimeout;
		return this;
	}
	
	OidcConfigDiscovery connectTimeout(long connectTimeout) {
		this.connectTimeout = connectTimeout;
		return this;
	}
	
	OidcConfigDiscovery credentials(UserName clientId, Password clientSecret) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		return this;
	}
	
	
	public OidcConfigDiscovery discover()  {
		
		Client client = newBuilder()
				 		.connectTimeout(connectTimeout, MILLISECONDS)
				 		.readTimeout(readTimeout, MILLISECONDS)
				 		.register(new JsonbDefaults())
				 		.build();
		
		JsonObject config = client.target(configEndpoint)
								  .request()
								  .accept(APPLICATION_JSON)
								  .header("Authorization", basicAuthentication(clientId, clientSecret))
								  .buildGet()
								  .invoke(JsonObject.class);
		
		authorizationEndpoint = config.getString("authorization_endpoint");
		tokenEndpoint = config.getString("token_endpoint");
		userInfoEndpoint = config.getString("userinfo_endpoint");
		// Read public key
		URI jwksEndpoint = URI.create(config.getString("jwks_uri"));

		
		try {
			JsonArray keys = client.target(jwksEndpoint)
					  				.request()
					  				.accept(APPLICATION_JSON)
					  				.header("Authorization", basicAuthentication(clientId, clientSecret))
					  				.buildGet()
					  				.invoke(JsonObject.class)
					  				.getJsonArray("keys");
			
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			
			Map<String,Key> keyById = new HashMap<>();
			for(int i=0; i < keys.size(); i++) {
				JsonObject key = keys.getJsonObject(i);
				SignatureAlgorithm algorithm = SignatureAlgorithm.valueOf(key.getString("alg"));
				X509Certificate crt = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(key.getJsonArray("x5c").getString(0))));
				keyById.put(key.getString("kid"), crt.getPublicKey());
			}
			
			this.keyResolver = new OidcSigningKeyResolver(keyById);
		} catch (Exception e) {
			LOG.severe("Cannot decode key chain "+e.getMessage());
		}
		
		return this;
		
	}
	
	public String getAuthorizationEndpoint() {
		return authorizationEndpoint;
	}
	
	public String getUserInfoEndpoint() {
		return userInfoEndpoint;
	}
	
	public String getTokenEndpoint() {
		return tokenEndpoint;
	}
	
	public SigningKeyResolver getKeys() {
		return keyResolver;
	}
	
	
}
