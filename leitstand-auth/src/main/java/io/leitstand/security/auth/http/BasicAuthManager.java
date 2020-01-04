/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The <code>BasicAuthManager</code> processes a request with HTTP Basic Authentication 
 * by means of
 * decoding the user credentials from the <code>Authorization</code> HTTP header and
 * verification of the user exists and the supplied password is correct.
 */
@Dependent
public class BasicAuthManager implements AccessTokenManager{

	@Inject
	private IdentityStore is;
	
	/**
	 * 
	 * @param request
	 * @param response
	 * @param auth
	 * @return
	 */
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
														  HttpServletResponse response) {
			
		Authorization auth = Authorization.valueOf(request);
		if(auth != null && auth.isBasic()) {
			BasicAuthentication basic = new BasicAuthentication(auth);
			return is.validate(new UsernamePasswordCredential(basic.getUserId().toString(), 
														 	  basic.getPassword()));
		}
		return NOT_VALIDATED_RESULT;
	}
	
}
