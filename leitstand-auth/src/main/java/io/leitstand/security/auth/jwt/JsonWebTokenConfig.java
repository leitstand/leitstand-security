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
package io.leitstand.security.auth.jwt;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.etc.FileProcessor.properties;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static java.util.Base64.getDecoder;

import java.time.Duration;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.commons.etc.Environment;
import io.leitstand.security.crypto.MasterSecret;
import io.leitstand.security.crypto.Secret;
/**
 * The JSON Web Token (JWT) configuration consists of the secret to sign the token, the token's time to live (ttl) and the token's refresh interval.
 * <p>
 * The configuration consists of the following properties:
 * <ul>
 * <li><code>jwt.secret</code> supplies the secret to sign a JWT. 
 * 	   The secret is encrypted with the configured {@link MasterSecret} and Base64 encoded.</li>
 * <li><code>jwt.ttl</code> defines the time-to-live (TTL) of a JWT. 
 *     The TTL is specified as <a href="https://docs.oracle.com/javase/8/docs/api/java/time/Duration.html#parse-java.lang.CharSequence-">duration</a>. 
 * 	   The default TTL is 1 hour.</li>
 * <li><code>jwt.refresh</code> defines the period where an expired JWT gets renewed and replaced by a new token.
 * 	   The refresh period is specified in the same format as the TTL and defaults to 60 seconds. </li>
 * </ul>
 * The configuration can either be specified in the <code>/etc/rbms/jwt.properties</code> file, as system properties or as environment variables.
 * 
 */
@ApplicationScoped
public class JsonWebTokenConfig {

	private static final String JWT_SECRET  = "jwt.secret";
	private static final String JWT_TTL	    = "jwt.ttl";
	private static final String JWT_REFRESH = "jwt.refresh";
	
	@Inject
	private Environment env;
	
	@Inject
	private MasterSecret master;
	
	private Secret secret;
	private Duration ttl;
	private Duration refresh;
	
	@PostConstruct
	protected void readJwtConfig() {
		Properties jwtConfig = env.loadFile("jwt.properties",
											properties());
		
		String secret64 = getSystemProperty(JWT_SECRET,
									  		jwtConfig.getProperty(JWT_SECRET));
		
		if(isNonEmptyString(secret64)) {
			byte[] cipher = getDecoder().decode(secret64);
			this.secret = new Secret(master.decrypt(cipher));
		} else {
			this.secret = new Secret(toUtf8Bytes("lab-environment"));
		}
		
		this.ttl = Duration.parse(getSystemProperty(JWT_TTL,
										 	  		jwtConfig.getProperty(JWT_TTL, 
												   			   			  "PT1H"))); 
		
		String configuredRefresh = getSystemProperty(JWT_REFRESH,
				 					 		   		 jwtConfig.getProperty(JWT_REFRESH)); 

		if(isNonEmptyString(configuredRefresh)) {
			this.refresh = Duration.parse(configuredRefresh);
		} else {
			this.refresh = Duration.ofSeconds(60);
		}
		
	}
	
	/**
	 * Returns the secret to sign the JWT.
	 * @return the secret to sign the JWT.
	 */
	public Secret getSecret() {
		return secret;
	}
	
	/**
	 * Returns the JWT time to live. 
	 * @return the JWT time to live.
	 */
	public Duration getTimeToLive() {
		return ttl;
	}
	
	/**
	 * Returns refresh interval for expired JWTs.
	 * @return refresh interval for expired JWTs.
	 */
	public Duration getRefreshInterval() {
		return refresh;
	}
	
}
