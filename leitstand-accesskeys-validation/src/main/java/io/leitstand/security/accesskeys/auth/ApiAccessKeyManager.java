/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.auth;

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.Role.SYSTEM;
import static java.util.logging.Level.FINE;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyDecoder;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.Authorization;
import io.leitstand.security.auth.jwt.JsonWebTokenSignatureException;

/**
 * The <code>AccessKeyManager</code> processes bearer authorization tokens 
 * by means of
 * restoring the {@link ApiAccessKey} from the bearer token,
 * checking whether the API access key is still valid and
 * allowed to perform the requested operation.
 *
 */
@Dependent
public class ApiAccessKeyManager implements AccessTokenManager {
	
	private static final Logger LOG = Logger.getLogger(ApiAccessKeyManager.class.getName());
	
	@Inject
	private ApiAccessKeyDecoder accesskeys;
	
	@Inject
	private AccessKeyAuthenticator authenticator;

	
	
	/**
	 * Decodes and validates a bearer token authorization
	 * @param request - the HTTP request
	 * @param response - the HTTP response
	 * @param auth - the Authorization HTTP header.
	 * @return <code>INVALID_RESULT</code> if the provided access key is invalid, 
	 * <code>NOT_VALIDATED_RESULT</Code> if the authorization header does not contain a bearer token and
	 * information about the authenticated user if the access key is valid.
	 */
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
													 	  HttpServletResponse response) {
		
		Authorization auth = Authorization.valueOf(request);
		if(auth != null && auth.isBearerToken()) {
			try {
				String bearerToken = auth.getCredentials();
				if(bearerToken.contains(".")) {
					return NOT_VALIDATED_RESULT;
				}
				ApiAccessKey accessKey = accesskeys.decode(auth.getCredentials());
				if(authenticator.isAllowed(request,accessKey)) {
					return new CredentialValidationResult(accessKey.getUserId().toString(),
														  asSet(SYSTEM));
				} 
			} catch (JsonWebTokenSignatureException e) {
				LOG.log(FINE,e.getMessage(),e);
			}
			return INVALID_RESULT;
		}
		return NOT_VALIDATED_RESULT;
	}
}
