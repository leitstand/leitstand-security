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
package io.leitstand.security.sso.oidc.config;

import static io.leitstand.security.auth.http.BasicAuthentication.basicAuthentication;
import static io.leitstand.security.sso.oidc.ReasonCode.OID0005E_CERTIFICATE_CHAIN_ERROR;
import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.logging.Logger.getLogger;
import static javax.ws.rs.client.ClientBuilder.newBuilder;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.net.URI;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import javax.json.JsonObject;
import javax.security.enterprise.credential.Password;
import javax.ws.rs.client.Client;

import com.nimbusds.jose.jwk.JWKSet;

import io.leitstand.commons.jsonb.JsonbDefaults;
import io.leitstand.security.auth.UserName;

/**
 * Discovers the OpenID/Connect configuration by attempting to load the configuration from 
 * the configured well-known configuration endpoint.
 */
public class OidcConfigDiscovery {

	private static final Logger LOG = getLogger(OidcConfigDiscovery.class.getName());
		
	private URI configEndpoint;
	private long readTimeoutMillis;
	private long connectTimeoutMillis;
	private UserName clientId;
	private Password clientSecret;
	private String issuer;
	private String authorizationEndpoint;
	private String userInfoEndpoint;
	private String tokenEndpoint;
	private String endSessionEndpoint;
	private JWKSet keys;
	
	/**
	 * Creates a <code>OidcConfigDiscovery</code> to discover the configuration from the given configuration endpoint.
	 * @param configEndpoint the configuration endpoint URL
	 */
	OidcConfigDiscovery(URI configEndpoint){
		this.configEndpoint = configEndpoint;
		this.readTimeoutMillis = 10000;
		this.connectTimeoutMillis = 1000;
	}
	
	/**
	 * Sets the read timeout.
	 * @param timeout read timeout
	 * @param unit read timeout unit
	 * @return a reference to this discovery object to continue with the discovery setup.
	 */
	OidcConfigDiscovery readTimeout(long timeout, TimeUnit  unit) {
		this.readTimeoutMillis = unit.toMillis(timeout);
		return this;
	}
	
    /**
     * Sets the connect timeout.
     * @param timeout connect timeout
     * @param unit connect timeout unit
     * @return a reference to this discovery object to continue with the discovery setup.
     */
	OidcConfigDiscovery connectTimeout(long timeout, TimeUnit unit) {
		this.connectTimeoutMillis = unit.toMillis(timeout);
		return this;
	}
	
	/**
	 * Sets the credentials to access the OpenID/Connect configuration.
	 * @param clientId the client identifier
	 * @param clientSecret the client secret to authenticate the configuration download
	 * @return a reference to this discovery object to continue with the discovery setup.
	 */
	OidcConfigDiscovery credentials(UserName clientId, Password clientSecret) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		return this;
	}
	
	
	/**
	 * Attempts to load the OpenID/Connect configuration.
	 * @return the discovered configuration
	 * @throws OidcConfigException if the configuration discovery fails 
	 */
	public OidcConfigDiscovery discover()  {
		
		Client client = newBuilder()
				 		.connectTimeout(connectTimeoutMillis, MILLISECONDS)
				 		.readTimeout(readTimeoutMillis, MILLISECONDS)
				 		.register(new JsonbDefaults())
				 		.build();
		
		try {
			JsonObject config = client.target(configEndpoint)
									  .request()
									  .accept(APPLICATION_JSON)
									  .header("Authorization", basicAuthentication(clientId, clientSecret))
									  .buildGet()
									  .invoke(JsonObject.class);
			issuer = config.getString("issuer");
			authorizationEndpoint = config.getString("authorization_endpoint");
			tokenEndpoint = config.getString("token_endpoint");
			userInfoEndpoint = config.getString("userinfo_endpoint");
			endSessionEndpoint = config.getString("end_session_endpoint");
			// Read public key
			URI jwksEndpoint = URI.create(config.getString("jwks_uri"));
	
			
			try {
				JsonObject jwks = client.target(jwksEndpoint)
						  				.request()
						  				.accept(APPLICATION_JSON)
						  				.header("Authorization", basicAuthentication(clientId, clientSecret))
						  				.buildGet()
						  				.invoke(JsonObject.class);
				
				this.keys = JWKSet.parse(jwks.toString());
			} catch (Exception e) {
				LOG.severe(format("%s: Cannot decode key chain: %s", 
								  OID0005E_CERTIFICATE_CHAIN_ERROR.getReasonCode(), 
								  e.getMessage()));
				throw new OidcConfigException(e, OID0005E_CERTIFICATE_CHAIN_ERROR);
			}
			return this;
		} finally {
			client.close();
		}
		
		
	}
	
	/**
	 * Returns the authorization endpoint URL.
	 * @return the authorization endpoint URL.
	 */
	public String getAuthorizationEndpoint() {
		return authorizationEndpoint;
	}
	
	/**
	 * Returns the user info endpoint URL.
	 * @return the user info endpoint URL.
	 */
	public String getUserInfoEndpoint() {
		return userInfoEndpoint;
	}
	
	/**
	 * Returns the token endpoint URL.
	 * @return the token endpoint URL.
	 */
	public String getTokenEndpoint() {
		return tokenEndpoint;
	}
	
	/**
	 * Returns the end-session endpoint URL.
	 * @return the end-session endpoint URL.
	 */
	public String getEndSessionEndpoint() {
		return endSessionEndpoint;
	}
	
	/** 
	 * Returns the access token issuer name.
	 * @return the access token issuer name.
	 */
	public String getIssuer() {
        return issuer;
    }
	
	public JWKSet getKeySet() {
	    return keys;
	}

}
