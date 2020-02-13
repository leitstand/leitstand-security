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

import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.security.auth.http.BasicAuthentication.basicAuthentication;
import static io.leitstand.security.auth.http.BearerToken.bearerToken;
import static io.leitstand.security.sso.oidc.OidcUserInfo.newUserInfo;
import static io.leitstand.security.sso.oidc.ReasonCode.OID0001E_CANNOT_CREATE_ACCESS_TOKEN;
import static io.leitstand.security.sso.oidc.ReasonCode.OID0004E_CANNOT_REFRESH_ACCESS_TOKEN;
import static io.leitstand.security.users.service.EmailAddress.emailAddress;
import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static javax.ws.rs.client.ClientBuilder.newBuilder;
import static javax.ws.rs.client.Entity.entity;
import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;

import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.json.JsonObject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.Form;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.jsonb.JsonbDefaults;
import io.leitstand.security.sso.oauth2.Oauth2AccessToken;

@RequestScoped
public class OidcClient {
	
	
	
	private static final Logger LOG = Logger.getLogger(OidcClient.class.getName());
	
	@Inject
	private OidcConfig config;
	
	private Client client;
	
	@PostConstruct
	protected void initClientBuilder() {
		client = newBuilder()
				 .connectTimeout(config.getConnectTimeout(), MILLISECONDS)
				 .readTimeout(config.getReadTimeout(), MILLISECONDS)
				 .register(new JsonbDefaults())
				 .build();
	}
	
	public Oauth2AccessToken getAccessToken(String code,
											String redirectUri) {
		
		Form request = new Form()
					   .param("grant_type", "authorization_code")
					   .param("code", code);
		if(isNonEmptyString(redirectUri)) {
			request.param("redirect_uri", redirectUri);
		}
		
		try {		
			return client.target(config.getTokenEndpoint())
						 .request()
						 .header("Authorization",basicAuthentication(config.getClientId(), config.getClientSecret()))
						 .post(entity(request,APPLICATION_FORM_URLENCODED),
							   Oauth2AccessToken.class);
		} catch (WebApplicationException e) {
			OidcError error = e.getResponse().readEntity(OidcError.class);			
			LOG.severe(() -> format("%s: Cannot obtain an access token due to %s: %s",
									OID0001E_CANNOT_CREATE_ACCESS_TOKEN.getReasonCode(),
									error.getError(),
									error.getErrorDescription()));
			throw new UnprocessableEntityException(OID0001E_CANNOT_CREATE_ACCESS_TOKEN,
												   error.getError(),
												   error.getErrorDescription());
		}
	}
	
	public Oauth2AccessToken refreshAccessToken(String refreshToken) {
		Form request = new Form()
					   .param("grant_type","refresh_token")
					   .param("refresh_token", refreshToken);
		
		try {
			return client.target(config.getTokenEndpoint())
						 .request()
						 .header("Authorization", basicAuthentication(config.getClientId(),config.getClientSecret()))
						 .post(entity(request,APPLICATION_FORM_URLENCODED),
							   Oauth2AccessToken.class);
		} catch (WebApplicationException e) {
			OidcError error = e.getResponse().readEntity(OidcError.class);
			LOG.severe(() -> format("%s: Cannot refresh access token due to %s: %s",
					OID0001E_CANNOT_CREATE_ACCESS_TOKEN.getReasonCode(),
					error.getError(),
					error.getErrorDescription()));
			throw new AccessDeniedException(OID0004E_CANNOT_REFRESH_ACCESS_TOKEN,
								   			error.getError(),
								   			error.getErrorDescription());

		}
	}
	
	public OidcUserInfo getUserInfo(Oauth2AccessToken accessToken) {
		try {
			JsonObject userData = client.target(config.getUserInfoEndpoint())
						 				.request()
						 				.header("Authorization", bearerToken(accessToken.getAccessToken()))
						 				.get(JsonObject.class);
			
			Jws<Claims> jws = config.parse(accessToken.getAccessToken());
			
			String name = userData.getString("name",null);
			String sub = userData.getString("sub",null);
			String preferredUsername = userData.getString("preferred_username",null);
			String givenName = userData.getString("given_name",null);
			String familyName = userData.getString("family_name",null);
			String email = userData.getString("email",null);
			String scope = jws.getBody().get("scope", String.class);
			
			return newUserInfo()
				   .withSub(sub)
				   .withPreferredUsername(preferredUsername)
				   .withName(name)
				   .withGivenName(givenName)
				   .withFamilyName(familyName)
				   .withEmail(emailAddress(email))
				   .withScopes(scope.split("\\s+"))
				   .build();
			
			
		} catch(WebApplicationException e) {
			OidcError error = e.getResponse().readEntity(OidcError.class);
			LOG.severe(() -> format("%s: Cannot obtain an access token due to %s: %s",
									OID0001E_CANNOT_CREATE_ACCESS_TOKEN.getReasonCode(),
									error.getError(),
									error.getErrorDescription()));
			throw new UnprocessableEntityException(OID0001E_CANNOT_CREATE_ACCESS_TOKEN,
												   error.getError(),
												   error.getErrorDescription());
		}
	}
	
}
