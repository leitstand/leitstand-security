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

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.etc.FileProcessor.properties;
import static io.leitstand.commons.model.ObjectUtil.optional;
import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.isEmptyString;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.http.LoginConfiguration.newLoginConfiguration;
import static io.leitstand.security.sso.oidc.OidcConfig.newOpenIdConfig;
import static java.lang.String.format;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getUrlDecoder;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.security.enterprise.credential.Password;

import io.jsonwebtoken.SigningKeyResolver;
import io.leitstand.commons.StartupListener;
import io.leitstand.commons.etc.Environment;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.http.LoginConfigurationProvider;
import io.leitstand.security.crypto.MasterSecret;
import io.leitstand.security.crypto.Secret;

@ApplicationScoped
public class OidcConfigProvider implements StartupListener {
	
	private static final Logger LOG = Logger.getLogger(OidcConfigProvider.class.getName());
	private static final String OIDC_CONFIGURATION_ENDPOINT	= "OIDC_CONFIGURATION_ENDPOINT";
	private static final String OIDC_AUTHORIZATION_ENDPOINT = "OIDC_AUTHORIZATION_ENDPOINT";
	private static final String OIDC_TOKEN_ENDPOINT	  	    = "OIDC_TOKEN_ENDPOINT";
	private static final String OIDC_USERINFO_ENDPOINT 	    = "OIDC_USERINFO_ENDPOINT";
	private static final String OIDC_TOKEN_SECRET			= "OIDC_TOKEN_SECRET"; 
	private static final String OIDC_TOKEN_X5C				= "OIDC_TOKEN_X5C";
	private static final String OIDC_CLIENT_ID 		 	    = "OIDC_CLIENT_ID";
	private static final String OIDC_CLIENT_SECRET 	 	    = "OIDC_CLIENT_SECRET";
	private static final String OIDC_READ_TIMEOUT		    = "OIDC_READ_TIMEOUT";
	private static final String OIDC_CONNECT_TIMEOUT		= "OIDC_CONNECT_TIMEOUT";
	private static final String OIDC_JWS_ALGORITHM 			= "OIDC_JWS_ALGORITHM";
	
	private static final long DEFAULT_OIDC_READ_TIMEOUT 	= 10000;
	private static final long DEFAULT_OIDC_CONNECT_TIMEOUT	= 10000;
	
	
	
	static PublicKey publicKey(String base64){
		if(isEmptyString(base64)) {
			return null;
		}
		return publicKey(getUrlDecoder().decode(base64));
	}
	
	
	static PublicKey publicKey(byte[] cert) {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			X509Certificate crt = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(getDecoder().decode(cert)));
			return crt.getPublicKey();
		} catch (CertificateException e) {
			// TODO Log
			return null;
		}
	}
	
	@Inject
	private Environment env;
	
	@Inject
	private MasterSecret masterSecret;
	
	@Inject
	private LoginConfigurationProvider loginConfigProvider;
	
	private OidcConfig config;
	
	@Override
	public void onStartup() {
		Properties properties = env.loadConfig("sso.properties", 
											   properties(),
											   () -> new Properties());
		// Read credentials to connect to the authorization service
		UserName clientId	  = userName(readOidcProperty(OIDC_CLIENT_ID, properties));
		Password clientSecret   = readClientSecret(properties);
		// Read timeout settings
		long connectTimeout = asLong(readOidcProperty(OIDC_CONNECT_TIMEOUT,properties),
													  DEFAULT_OIDC_CONNECT_TIMEOUT);
		long readTimeout 	= asLong(readOidcProperty(OIDC_READ_TIMEOUT, properties),
													  DEFAULT_OIDC_READ_TIMEOUT);
		
		// Read configured endpoints and certificate to verify tokens.
		String authorizationEndpoint = readOidcProperty(OIDC_AUTHORIZATION_ENDPOINT,properties);
		String tokenEndpoint		 = readOidcProperty(OIDC_TOKEN_ENDPOINT,properties);
		String userInfoEndpoint		 = readOidcProperty(OIDC_USERINFO_ENDPOINT, properties);
//		Secret tokenSecret			 = readTokenSecret(properties);
//		PublicKey tokenKey			 = publicKey(readOidcProperty(OIDC_TOKEN_CERT,properties));
//		String algorithm			 = readOidcProperty(OIDC_JWS_ALGORITHM, properties);
		SigningKeyResolver keys = null;
		
		String configEndpoint = readOidcProperty(OIDC_CONFIGURATION_ENDPOINT,properties);
		if(isNonEmptyString(configEndpoint)) {
			// Discover all endpoints and configured secrets from the specified endpoint.
			// Replaces all statically configured values.
			OidcConfigDiscovery discovery = new OidcConfigDiscovery(URI.create(configEndpoint))
											.connectTimeout(connectTimeout)
											.readTimeout(readTimeout)
											.credentials(clientId,clientSecret)
											.discover();
											
			authorizationEndpoint = discovery.getAuthorizationEndpoint();
			tokenEndpoint = discovery.getTokenEndpoint();
			userInfoEndpoint = discovery.getUserInfoEndpoint();
			keys = discovery.getKeys();
		}
		
		if(isOpenIdEnabled(authorizationEndpoint, 
						   tokenEndpoint, 
						   userInfoEndpoint,
						   clientId,
						   clientSecret,
						   keys)) {

			try {
				config = newOpenIdConfig()
						 .withAuthorizationEndpoint(new URI(authorizationEndpoint))
						 .withTokenEndpoint(new URI(tokenEndpoint))
						 .withUserInfoEndpoint(new URI(userInfoEndpoint))
						 .withClientId(clientId)
						 .withClientSecret(clientSecret)
						 .withConnectTimeout(connectTimeout)
						 .withReadTimeout(readTimeout)
						 .withSigningKeys(keys)
						 .build();

				LOG.info("OpenID/connect enabled. ");
				LOG.info(format("OpenID authorization endpoint  : %s",authorizationEndpoint));
				LOG.info(format("OpenID token endpoint ........ : %s",tokenEndpoint));
				LOG.info(format("OpenID user info endpoint .... : %s",userInfoEndpoint));
				LOG.info(format("OpenID connect timeout ....... : %d ms", connectTimeout));
				LOG.info(format("OpenID read timeout .......... : %d ms", readTimeout));
				LOG.info(format("OpenID client ID ............. : %s",clientId));
				LOG.info(format("OpenID client secret ......... : %s", clientSecret == null ? "not specified" : "specified"));
				
				
			} catch (URISyntaxException e) {
				LOG.severe(format("Malformed URL: %s",e));
			}
			loginConfigProvider.setLoginConfiguration(newLoginConfiguration()
													  .withLoginView(authorizationEndpoint)
													  .withOidcClientId(clientId.toString())
													  .withOidcEnabled(true).build());
		} 
		
	}

	static String readOidcProperty(String propertyName, Properties properties) {
		return optional(getSystemProperty(propertyName,properties.getProperty(propertyName)),
						String::trim);
	}
	
	static long asLong(String s, long defaultValue) {
		if(isEmptyString(s)) {
			return defaultValue;
		}
		try {
			return Long.parseLong(s);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}
	
	
	Password readClientSecret(Properties properties) {
		String clientSecret   = getSystemProperty(OIDC_CLIENT_SECRET,properties.getProperty(OIDC_CLIENT_SECRET));
		if(isNonEmptyString(clientSecret)) {
			try {
				return new Password(fromUtf8Bytes(masterSecret.decrypt(getDecoder().decode(clientSecret))));
			} catch (Exception e) {
				LOG.warning(() -> format("Cannot decrypt value of %s. Use client secret as specified (assuming secret was specified in plain text). Encrypted secrets must be Base64 encoded.",OIDC_CLIENT_SECRET));
				return new Password(clientSecret);
			}
		}
		return null;
	}
	
	Secret readTokenSecret(Properties properties) {
		String tokenSecret   = getSystemProperty(OIDC_TOKEN_SECRET,properties.getProperty(OIDC_TOKEN_SECRET));
		if(isNonEmptyString(tokenSecret)) {
			try {
				return new Secret(masterSecret.decrypt(getDecoder().decode(tokenSecret)));
			} catch (Exception e) {
				LOG.warning(() -> format("Cannot decrypt value of %s. Use client secret as specified (assuming secret was specified in plain text). Encrypted secrets must be Base64 encoded.",OIDC_CLIENT_SECRET));
				return new Secret(getDecoder().decode(tokenSecret));
			}
		}
		return null;
	}
	
	
	boolean isOpenIdEnabled(String authorizationEndpoint, 
							String tokenEndpoint, 
							String userInfoEndpoint,
							UserName clientId,
							Password clientSecret,
							SigningKeyResolver keys) {
		return isNonEmptyString(authorizationEndpoint) 
			   && isNonEmptyString(tokenEndpoint) 
			   && isNonEmptyString(userInfoEndpoint)
			   && clientId != null
			   && clientSecret != null
			   && keys != null;
	}
	
	@Produces
	OidcConfig getOpenIdConfig() {
		return config;
	}
}
