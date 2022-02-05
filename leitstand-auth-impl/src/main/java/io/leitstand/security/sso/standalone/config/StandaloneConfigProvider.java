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
package io.leitstand.security.sso.standalone.config;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.rs.ResourceUtil.tryParseInt;
import static io.leitstand.security.rsa.RsaKeys.PEM_FILE_PROCESSOR;
import static io.leitstand.security.rsa.RsaKeys.exportKeyPair;
import static io.leitstand.security.rsa.RsaKeys.generateRsaKeyPair;
import static io.leitstand.security.sso.standalone.config.StandaloneLoginConfig.STANDALONE_LOGIN_KEY_ID;
import static io.leitstand.security.sso.standalone.config.StandaloneLoginConfig.newStandaloneLoginConfig;

import java.security.KeyPair;
import java.time.Duration;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import io.leitstand.commons.StartupListener;
import io.leitstand.commons.etc.Environment;
import io.leitstand.security.auth.jwt.DefaultRsaJwtService;
import io.leitstand.security.sso.oidc.config.OidcConfig;

/**
 * The <code>StandaloneLoginProvider</code> creates a {@link StandaloneLoginConfig} 
 * if not OpenId/Connect authorization service is configured.
 * <p>
 * The standalone login configuration uses <em>RS256</em> signed access tokens.
 * The RSA key pair is read from the <em>LEITSTAND_HOME/login.pem</em> file.
 * The provider creates a 2048-bit RSA key pair and creates the <em>login.pem</em> file in case the file does not exist.
 * <p>
 * An access token expires after 3600 seconds (= 60 minutes = 1 hour) and gets renewed if a token is expired but 
 * does not exceed the refresh period of 60 seconds.
 * <p>
 * The <code>JWS_TTL</code> environment property allows changing the access token time-to-live duration. 
 * The <code>JWS_REFRESH</code> environment property allows changing the grace period for renewing an expired access token.
 * 
 */
@ApplicationScoped
public class StandaloneConfigProvider implements StartupListener {
	
    
	private static final int ACCESS_TOKEN_KEY_SIZE = 2048;

    private static final String ACCESS_TOKEN_KEY_PEM_FILE = "login.pem";


	private static final String STANDALONE_JWS_TTL = "JWS_TTL";
	private static final String STANDALONE_JWS_REFRESH = "JWS_REFRESH";
		
	@Inject
	private Environment env;
	
	@Inject
	private OidcConfig oidc;
	
	@Produces
    private StandaloneLoginConfig config;

	
    /**
     * Reads the standalone login configuration if no OpenID/Connect authorization service is configured.
     */
    @Override
	public void onStartup() {		
	    
	    if (oidc != null) {
	        // No action required if OpenId/Connect is enabled.
	        return;
	    }
	    
	    KeyPair keyPair = readAccessTokenKeyPair();
		
	    DefaultRsaJwtService jwtService = new DefaultRsaJwtService(keyPair, STANDALONE_LOGIN_KEY_ID);
	    
		Duration jwtTtl = Duration.ofSeconds(tryParseInt(getSystemProperty(STANDALONE_JWS_TTL), 3600)); 
		Duration jwtRefresh = Duration.ofSeconds(tryParseInt(getSystemProperty(STANDALONE_JWS_REFRESH),60)); 

		this.config = newStandaloneLoginConfig()
		              .withRefresh(jwtRefresh)
		              .withTimeToLive(jwtTtl)
		              .withJwtService(jwtService)
		              .withKeySet(jwtService.getKeySet())
		              .build();
		
	}

    private KeyPair readAccessTokenKeyPair() {
        if (env.fileExists(ACCESS_TOKEN_KEY_PEM_FILE)) {
	        return env.loadConfig(ACCESS_TOKEN_KEY_PEM_FILE, PEM_FILE_PROCESSOR);
	    }
        
        KeyPair keyPair = generateRsaKeyPair(ACCESS_TOKEN_KEY_SIZE);
	    env.storeFile(ACCESS_TOKEN_KEY_PEM_FILE, exportKeyPair(keyPair));
	    return keyPair;
    }
    
    
}
