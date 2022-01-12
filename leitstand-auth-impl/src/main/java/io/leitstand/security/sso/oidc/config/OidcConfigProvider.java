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

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.etc.FileProcessor.properties;
import static io.leitstand.commons.model.ObjectUtil.optional;
import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.isEmptyString;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.commons.model.StringUtil.trim;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.sso.oidc.ReasonCode.OID0005E_CERTIFICATE_CHAIN_ERROR;
import static io.leitstand.security.sso.oidc.ReasonCode.OID0007E_CANNOT_READ_JWKS;
import static io.leitstand.security.sso.oidc.config.OidcConfig.newOpenIdConfig;
import static java.lang.String.format;
import static java.security.cert.CertificateFactory.getInstance;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getUrlDecoder;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.logging.Level.FINE;
import static java.util.logging.Logger.getLogger;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;

import io.leitstand.commons.StartupListener;
import io.leitstand.commons.etc.Environment;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jwt.DefaultJwksDecoder;
import io.leitstand.security.auth.jwt.JwtDecoder;
import io.leitstand.security.crypto.MasterSecret;

/**
 * A provider for the OpenID/Connect configuration.
 * <p>
 * The provider either reads the configuration from a configured configuration endpoint or reads the entire configuration from environment variables.
 * Alternatively, the variables below can also be stored in <code>LEISTAND_ETC/sso.properties</code>.
 * <table>
 *  <caption>OpenID/Connect environment variables</caption>
 *  <tr>
 *      <th>Environment Variable</th>
 *      <th>Description</th>
 *  </tr>
 *  <tr>
 *      <td>OIDC_CONFIGURATION_ENDPOINT</td>
 *      <td>Configuration endpoint URL. If present, the configuration provider attempts to read the configuration from this URL.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_CLIENT_ID</td>
 *      <td>Client ID to authenticate all requests from Leitstand to the OpenID/Connect server</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_CLIENT_SECRET</td>
 *      <td>Client secret to authenticate all requests from Leitstand to the OpenID/Connect server</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_CONNECT_TIMEOUT</td>
 *      <td>Connect timeout for all OpenID/Connect server requests in milliseconds.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_READ_TIMEOUT</td>
 *      <td>Read timeout for all OpenID/Connect server requests in milliseconds.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_AUTHORIZATION_ENDPOINT</td>
 *      <td>Authorization endpoint URL. This property is obsolete if a OIDC_CONFIGURATION_ENDPOINT is specified.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_TOKEN_ENDPOINT</td>
 *      <td>Token endpoint URL. This property is obsolete if a OIDC_CONFIGURATION_ENDPOINT is specified.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_USERINFO_ENDPOINT</td>
 *      <td>User-info endpoint URL. This property is obsolete if a OIDC_CONFIGURATION_ENDPOINT is specified.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_ENDSESSION_ENDPOINT</td>
 *      <td>End-session endpoint URL. This property is obsolete if a OIDC_CONFIGURATION_ENDPOINT is specified.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_JWS_ALGORITHM</td>
 *      <td>The algorithm to sign the JWT tokens. This property is obsolete if a OIDC_CONFIGURATION_ENDPOINT is specified.</td>
 *  </tr>
 *  <tr>
 *      <td>OIDC_JWKS_URL</td>
 *      <td>The JSON Web Key Set location. This property is obsolete if a OIDC_CONFIGURATION_ENDPOINT is specified.</td>
 *  </tr>
 * </table>
 * The settings read from the configuration endpoint have precedence over manually applied settings. 
 * In order to avoid troubles it is strongly recommended to not combine the configuration endpoint with explicit settings. 
 * 
 * 
 */
@ApplicationScoped
public class OidcConfigProvider implements StartupListener {
	
	private static final Logger LOG = getLogger(OidcConfigProvider.class.getName());
	private static final String OIDC_CONFIGURATION_ENDPOINT	= "OIDC_CONFIGURATION_ENDPOINT";
	private static final String OIDC_CLIENT_ID 		 	    = "OIDC_CLIENT_ID";
	private static final String OIDC_CLIENT_SECRET 	 	    = "OIDC_CLIENT_SECRET";
	private static final String OIDC_CONNECT_TIMEOUT		= "OIDC_CONNECT_TIMEOUT";
	private static final String OIDC_READ_TIMEOUT		    = "OIDC_READ_TIMEOUT";
	
	private static final String OIDC_AUTHORIZATION_ENDPOINT = "OIDC_AUTHORIZATION_ENDPOINT";
	private static final String OIDC_TOKEN_ENDPOINT	  	    = "OIDC_TOKEN_ENDPOINT";
	private static final String OIDC_USERINFO_ENDPOINT 	    = "OIDC_USERINFO_ENDPOINT";
	private static final String OIDC_ENDSESSION_ENDPOINT	= "OIDC_ENDSESSION_ENDPOINT";
	private static final String OIDC_JWS_ALGORITHM 			= "OIDC_JWS_ALGORITHM";
	private static final String OIDC_JWKS                   = "OIDC_JWKS_URL";
	
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
			CertificateFactory cf = getInstance("X509");
			X509Certificate crt = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(getDecoder().decode(cert)));
			return crt.getPublicKey();
		} catch (CertificateException e) {
			LOG.severe(format("%s: Cannot process certificate. Reason; %s", 
							  OID0005E_CERTIFICATE_CHAIN_ERROR.getReasonCode(),
							  e.getMessage()));
			LOG.log(FINE,e.getMessage(),e);
			throw new OidcConfigException(e, OID0005E_CERTIFICATE_CHAIN_ERROR, e.getMessage());
		}
	}
	
	@Inject
	private Environment env;
	
	@Inject
	private MasterSecret masterSecret;
	
	
	private OidcConfig config;
	
	/**
	 * Discovers the OpenID/Connect configuration.
	 */
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
		String issuer = "leitstand";
		String authorizationEndpoint = readOidcProperty(OIDC_AUTHORIZATION_ENDPOINT,properties);
		String tokenEndpoint		 = readOidcProperty(OIDC_TOKEN_ENDPOINT,properties);
		String userInfoEndpoint		 = readOidcProperty(OIDC_USERINFO_ENDPOINT, properties);
		String endSessionEndpoint	 = readOidcProperty(OIDC_ENDSESSION_ENDPOINT,properties);
		JWSAlgorithm algorithm       = readJWSAlgorithm(properties);
        JWKSet keys = null;
        JwtDecoder decoder = null;
		
		String configEndpoint = readOidcProperty(OIDC_CONFIGURATION_ENDPOINT,properties);
		if(isNonEmptyString(configEndpoint)) {
			// Discover all endpoints and configured secrets from the specified endpoint.
			// Replaces all statically configured values.
			OidcConfigDiscovery discovery = new OidcConfigDiscovery(URI.create(configEndpoint))
											.connectTimeout(connectTimeout, MILLISECONDS)
											.readTimeout(readTimeout, MILLISECONDS)
											.credentials(clientId,clientSecret)
											.discover();
											
			issuer = discovery.getIssuer();
			authorizationEndpoint = discovery.getAuthorizationEndpoint();
			tokenEndpoint = discovery.getTokenEndpoint();
			userInfoEndpoint = discovery.getUserInfoEndpoint();
			endSessionEndpoint = discovery.getEndSessionEndpoint();
			keys = discovery.getKeySet();
			decoder = new DefaultJwksDecoder(algorithm, keys);

		} else {
	        keys = readKeySet(properties);
	        decoder = new DefaultJwksDecoder(algorithm, keys);
		}
		
		if(isOpenIdEnabled(authorizationEndpoint, 
						   tokenEndpoint, 
						   userInfoEndpoint,
						   endSessionEndpoint,
						   clientId,
						   clientSecret,
						   decoder)) {

			try {
				config = newOpenIdConfig()
				         .withIssuer(issuer)
						 .withAuthorizationEndpoint(new URI(authorizationEndpoint))
						 .withTokenEndpoint(new URI(tokenEndpoint))
						 .withUserInfoEndpoint(new URI(userInfoEndpoint))
						 .withEndSessionEndpoint(new URI(endSessionEndpoint))
						 .withClientId(clientId)
						 .withClientSecret(clientSecret)
						 .withConnectTimeout(connectTimeout,MILLISECONDS)
						 .withReadTimeout(readTimeout,MILLISECONDS)
						 .withDecoder(decoder)
						 .withKeySet(keys)
						 .build();

				LOG.info("OpenID/Connect enabled.");
				LOG.info(format("OpenID access token issuer ... : %s", issuer));
				LOG.info(format("OpenID authorization endpoint  : %s", authorizationEndpoint));
				LOG.info(format("OpenID token endpoint ........ : %s", tokenEndpoint));
				LOG.info(format("OpenID user-info endpoint .... : %s", userInfoEndpoint));
				LOG.info(format("OpenID end-session endpoint .. : %s", endSessionEndpoint));
				LOG.info(format("OpenID connect timeout ....... : %d ms", connectTimeout));
				LOG.info(format("OpenID read timeout .......... : %d ms", readTimeout));
				LOG.info(format("OpenID client ID ............. : %s",clientId));
				LOG.info(format("OpenID client secret ......... : %s", clientSecret == null ? "not specified" : "specified"));
				
				
			} catch (URISyntaxException e) {
				LOG.severe(format("Malformed URL: %s",e));
			}
		} 
		
	}

	private JWSAlgorithm readJWSAlgorithm(Properties properties) {
	    String alg = trim(properties.getProperty(OIDC_JWS_ALGORITHM));
	    if (isEmptyString(alg)) {
	        return RS256;
	    }
	    return JWSAlgorithm.parse(alg); 
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
	
	JWKSet readKeySet(Properties properties) {
	    String jwksLocation = trim(getSystemProperty(OIDC_JWKS));
	    try {
	        if (isEmptyString(jwksLocation)) {
	            return null;
	        }
    	    return JWKSet.load(new URL(jwksLocation));
	    } catch (Exception e) {
	        throw new OidcConfigException(e, OID0007E_CANNOT_READ_JWKS, jwksLocation);
	    }
	}
	    
	
	boolean isOpenIdEnabled(String authorizationEndpoint, 
							String tokenEndpoint, 
							String userInfoEndpoint,
							String endSessionEndpoint,
							UserName clientId,
							Password clientSecret,
							JwtDecoder decoder) {
		return isNonEmptyString(authorizationEndpoint) 
			   && isNonEmptyString(tokenEndpoint) 
			   && isNonEmptyString(userInfoEndpoint)
			   && isNonEmptyString(endSessionEndpoint)
			   && clientId != null
			   && clientSecret != null
			   && decoder != null;
	}
	
	/**
	 * Makes the OpenID/Connect configuration available as CDI managed bean.
	 * @return
	 */
	@Produces
	OidcConfig getOpenIdConfig() {
		return config;
	}
}
