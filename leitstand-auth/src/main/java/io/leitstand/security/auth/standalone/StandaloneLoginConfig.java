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
package io.leitstand.security.auth.standalone;

import static io.jsonwebtoken.Jwts.builder;
import static io.leitstand.commons.etc.Environment.emptyEnvironment;
import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.etc.FileProcessor.properties;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.security.crypto.SecureHashes.sha256;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmac;
import static java.lang.Boolean.parseBoolean;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getUrlEncoder;
import static java.util.logging.Logger.getLogger;

import java.security.Key;
import java.time.Duration;
import java.util.Properties;
import java.util.function.Supplier;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.leitstand.commons.etc.Environment;
import io.leitstand.security.crypto.MasterSecret;
import io.leitstand.security.crypto.MasterSecretException;
import io.leitstand.security.crypto.Secret;
import io.leitstand.security.mac.MessageAuthenticationCode;

@ApplicationScoped
public class StandaloneLoginConfig {
	
	private static final Logger LOG = getLogger(StandaloneLoginConfig.class.getName());

	private static final String STANDALONE_JWS_SECRET = "JWS_SECRET";
	private static final String STANDALONE_JWS_TTL = "JWS_TTL";
	private static final String STANDALONE_JWS_REFRESH = "JWS_REFRESH";
	private static final String STANDALONE_JWS_SIGNATURE_ALGORITHM = "JWS_ALGORITHM";
	private static final String STANDALONE_BASIC_AUTH_ENABLED = "BASIC_AUTH_ENABLED";
	private static final String STANDALONE_API_ACCESSKEY_SECRET = "API_SECRET";
	private static final String STANDALONE_API_ACCESSKEY_SIGNATURE_ALGORITHM = "API_ALGORITHM";
		
	@Inject
	private Environment env;
	
	@Inject
	private MasterSecret master;
	
	private Duration jwsTtl;
	private Duration jwsRefresh;
	private Key jwsKey;
	private Key apiKey;
	@Deprecated
	private Supplier<MessageAuthenticationCode> apiMac;
	private boolean basicAuthEnabled;
	
	public static StandaloneLoginConfig createDefaultLoginConfig() {
	    StandaloneLoginConfig config = new StandaloneLoginConfig();
	    config.env = emptyEnvironment();
	    config.master = new MasterSecret(config.env);
	    config.readProperties(new Properties());
	    return config;
	}
	
	@PostConstruct
	protected void readStandaloneConfig() {		
		Properties jwtConfig = env.loadFile("login.properties",
											properties());
		
		readProperties(jwtConfig);
	}

	private void readProperties(Properties jwtConfig) {
		SignatureAlgorithm alg = SignatureAlgorithm.valueOf(getSystemProperty(STANDALONE_JWS_SIGNATURE_ALGORITHM,
															jwtConfig.getProperty(STANDALONE_JWS_SIGNATURE_ALGORITHM,"HS256")));
		
		// Don't specify a default STANDALONE_JWS_SECRET to disable JWS
		String secret64 = getSystemProperty(STANDALONE_JWS_SECRET,
									  		jwtConfig.getProperty(STANDALONE_JWS_SECRET));
		
		this.jwsKey = createKey(alg,secret64);
		
		
		this.jwsTtl = Duration.parse(getSystemProperty(STANDALONE_JWS_TTL,
										 	  		jwtConfig.getProperty(STANDALONE_JWS_TTL,"PT1H"))); 
		
		this.jwsRefresh = Duration.parse(getSystemProperty(STANDALONE_JWS_REFRESH,
				 					 		   		    jwtConfig.getProperty(STANDALONE_JWS_REFRESH,"PT1M"))); 

		this.basicAuthEnabled = parseBoolean(getSystemProperty(STANDALONE_BASIC_AUTH_ENABLED,
															   jwtConfig.getProperty(STANDALONE_BASIC_AUTH_ENABLED,"true")));	
		
		alg = SignatureAlgorithm.valueOf(getSystemProperty(STANDALONE_API_ACCESSKEY_SIGNATURE_ALGORITHM,
										 jwtConfig.getProperty(STANDALONE_API_ACCESSKEY_SIGNATURE_ALGORITHM,"HS256")));

		secret64 = getSystemProperty(STANDALONE_API_ACCESSKEY_SECRET,
									 jwtConfig.getProperty(STANDALONE_API_ACCESSKEY_SECRET,"changeit"));
		
		
		this.apiKey = createKey(alg,secret64);
		if(secret64 != null) {
		    // Compute apiMac for backward compatibility.
            SecretKeySpec apiHmacKey = new SecretKeySpec(decodeSecret(secret64).toByteArray(), 
                                                         alg.getJcaName());
		    this.apiMac = () -> {
				return hmac(apiHmacKey);
			};
		}
	}

	private SecretKeySpec createKey(SignatureAlgorithm alg, String secret64) {
		if(isNonEmptyString(secret64)) {
			Secret secret = decodeSecret(secret64);
			if(secret.bitlength() < alg.getMinKeyLength()) {
				LOG.warning("Configured secret undershorts the encouraged minimum key length of "+alg.getMinKeyLength());
				// Extend the secret to work around the problem.
				secret = new Secret(sha256().hash(secret.toByteArray()));
			}
			return new SecretKeySpec(secret.toByteArray(), alg.getJcaName());
		} 
		return null;
	}


	private Secret decodeSecret(String secret) {
		byte[] cipher = getDecoder().decode(secret);
		try {
			return new Secret(master.decrypt(cipher));
		} catch (MasterSecretException e) {
			return new Secret(cipher);
		}
	}
	
	public boolean isApiAccessKeysEnabled() {
		return apiMac != null;
	}
	
	public boolean isBasicAuthEnabled() {
		return basicAuthEnabled;
	}
	
	public boolean isJwsEnabled() {
		return jwsKey != null;
	}


	
	public Jws<Claims> decodeAccessToken(String token){
		JwtParser parser = Jwts.parserBuilder()
				   			   .setSigningKey(jwsKey)
				   			   .build();
		return parser.parseClaimsJws(token);
	}

   public Jws<Claims> decodeApiAccessKey(String token){
        JwtParser parser = Jwts.parserBuilder()
                               .setSigningKey(apiKey)
                               .build();
        return parser.parseClaimsJws(token);
    }

	
	public String signAccessToken(JwtBuilder builder) {
		return builder.signWith(jwsKey).compact();
	}
	
	public String signAccessToken(Claims claims) {
	    return signAccessToken(builder().addClaims(claims));
	}

    public String signApiAccessKey(JwtBuilder builder) {
        return builder.signWith(apiKey).compact();
	}
	    
	public String signApiAccessKey(Claims claims) {
	    return signApiAccessKey(builder().addClaims(claims));
	}

	
	@Deprecated
	public String apiKeyHmac(String key) {
		return getUrlEncoder().encodeToString(apiMac.get().sign(key));
	}
	
	public Duration getTimeToLive() {
		return jwsTtl;
	}


	public Duration getRefreshInterval() {
		return jwsRefresh;
	}


	

}
