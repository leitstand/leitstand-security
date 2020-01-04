/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oauth2;

import static java.util.Collections.emptySet;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.logging.Level.FINE;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.Authorization;
import io.leitstand.security.auth.jwt.JsonWebTokenDecoder;
import io.leitstand.security.auth.jwt.JsonWebTokenSignatureException;

@Dependent
public class AuthorizationCodeManager implements AccessTokenManager{
	
	private static final Logger LOG = Logger.getLogger(AuthorizationCodeManager.class.getName());

	@Inject
	private JsonWebTokenDecoder jwtDecoder;

	@Override
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
														  HttpServletResponse response) {
		
		Authorization auth = Authorization.valueOf(request);
		
		if(auth == null) {
			return NOT_VALIDATED_RESULT;
		}
		
		String bearerToken = auth.getCredentials();
		if(bearerToken.indexOf('.') >= 0) {
			try {
				AuthorizationCode authCode = jwtDecoder.decode(AuthorizationCode.class, 
															   AuthorizationCode.Payload.class, 
															   bearerToken);
				if(authCode.isOlderThan(60,SECONDS)) {
					return INVALID_RESULT;
				}
				return new CredentialValidationResult(authCode.getUserId().toString(),
													  emptySet());
			} catch(JsonWebTokenSignatureException e) {
				LOG.log(FINE,e.getMessage(),e);
				return INVALID_RESULT;
			}
		}
		
		return NOT_VALIDATED_RESULT;

	}

}
