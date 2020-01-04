/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.jsonb.IsoDateAdapter.isoDateFormat;
import static io.leitstand.security.auth.http.AccessToken.newAccessToken;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.util.logging.Level.FINER;
import static java.util.logging.Logger.getLogger;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import java.util.Date;
import java.util.Set;
import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.http.AccessToken.Payload;
import io.leitstand.security.auth.jwt.JsonWebToken;
import io.leitstand.security.auth.jwt.JsonWebTokenConfig;
import io.leitstand.security.auth.jwt.JsonWebTokenDecoder;
import io.leitstand.security.auth.jwt.JsonWebTokenEncoder;
import io.leitstand.security.auth.jwt.JsonWebTokenSignatureException;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

/**
 * The <code>CookieManager</code> maintains the JWT cookie to authenticate subsequent request after a successful login request.
 * <p>
 * The <code>CookieManager</code> has the following responsibilities:
 * <ul>
 * 	<li>Creation of an {@link AccessToken} for an authenticated user, encode it as JSON Web Token (JWT) in a secure session cookie.</li>
 *  <li>Renewing a cookie periodically if the user continuously works with RBMS.  By that, a cookie expires if a user forgets to logoff, while an active user is not periodically prompted for login credentials</li>
 *  <li>Deleting a cookie after the user logged off.</li>
 *  <li>Decoding and verification of an access token restored from the cookie.</li>
 * </ul>
 * The cookie name defaults to <code>rtb-access</code> and can be overriden by specifying the <code>rbms.access.token.cookie.name</code> environment variable.
 */
@Dependent
public class CookieManager implements AccessTokenManager{
	
	private static final String JWT_COOKIE = getSystemProperty("rbms.access.token.cookie","rtb-access");
	private static final Logger LOG = getLogger(CookieManager.class.getName());
	
	/**
	 * Scans a HTTP request for a <code>rtb-access</code> cookie.
	 * @param request - the HTTP request
	 * @return the <code>rtb-access</code> cookie or 
	 * 		   <code>null</code> if no <code>rtb-access</code> cookie is present.
	 */
	static Cookie findAccessToken(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		// Cookies is null, if request sends no cookie information
		if(cookies == null) {
			return null;
		}
		for(Cookie cookie:cookies) {
			if(cookie.getName().equals(JWT_COOKIE)) {
				return cookie;
			}
		}
		return null;
	}
	
	@Inject
	private JsonWebTokenDecoder decoder;
	
	@Inject
	private JsonWebTokenEncoder encoder;
	
	@Inject
	private UserRegistry userRegistry;
	
	
	
	@Inject
	private JsonWebTokenConfig config;
	
	/**
	 * Creates an {@link AccessToken} for the given authenticated user with the given roles.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param userId the user ID of the authenticate user
 	 * @param roles the roles of the authenticated user.
	 */
	@Override
	public boolean issueAccessToken(HttpServletRequest request,
									HttpServletResponse response,
									UserId userId,
									Set<String> roles) {
		
		UserInfo user = userRegistry.getUserInfo(userId);

		Date expiryDate = computeExpiryDate(user);
		
		// Create JWT access token and send it as a cookie to the caller.
		JsonWebToken<Payload> token = newAccessToken()
									  .withUserId(userId)
									  .withRoles(roles)
									  .withDateExpiry(expiryDate)
									  .build();
		String jwt = encoder.encode(token);
		writeCookie(request, 
					response, 
					jwt,
					(int)(expiryDate.getTime() - currentTimeMillis())/1000);
		
		LOG.fine(() -> format("User %s login succeeded!",userId));
		return true;
	}

	private Date computeExpiryDate(UserInfo user){
		if(user.getAccessTokenTtl() != null && user.getAccessTokenTtlUnit() != null) {
			return new Date(currentTimeMillis()+user.getAccessTokenTtlUnit().toMillis(user.getAccessTokenTtl()));
		}
		return new Date(currentTimeMillis()+config.getTimeToLive().toMillis());
	}
	
	
	private void writeCookie(HttpServletRequest request, 
							 HttpServletResponse response, 
							 String jwt,
							 int maxAgeSeconds) {
		Cookie cookie = findAccessToken(request);
		if(cookie != null) {
			cookie.setValue(jwt);
			cookie.setMaxAge(maxAgeSeconds);
			response.addCookie(cookie);
		} else {
			cookie = new Cookie(JWT_COOKIE, jwt);
			cookie.setHttpOnly(true);
			cookie.setSecure(request.isSecure());
			cookie.setPath("/");
			cookie.setMaxAge(maxAgeSeconds);
			response.addCookie(cookie);
		}
	}


	/**
	 * Deletes the login cookie and removes it from the browser.
	 * @param request the HTTP request
	 * @param response the HTTP response
 	 */
	@Override
	public void invalidateAccessToken(HttpServletRequest request, 
									  HttpServletResponse response) {
		Cookie cookie = new Cookie(JWT_COOKIE,"");
		cookie.setHttpOnly(true);
		cookie.setSecure(request.isSecure());
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);		
	}


	/**
	 * Decodes and validates the access token from the cookie.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return <code>INVALID_RESULT</code> if no access token is available or the access token is invalid or expired, otherwise information about the authenticated user and its roles.
	 */
	@Override
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
												   		  HttpServletResponse response) {
		Cookie jwt = findAccessToken(request);		
		if(jwt == null) {
			LOG.fine(() -> format("No %s cookie available.",JWT_COOKIE));
			return NOT_VALIDATED_RESULT;
		}
		try {
			AccessToken token = decoder.decode(AccessToken.class, 
											   AccessToken.Payload.class,
											   jwt.getValue());
			if(token.isExpired()) {
				LOG.fine(() -> format("Token for user %s created at %s expired.",
									  token.getUserId(),
									  isoDateFormat(token.getDateCreated())));
				invalidateAccessToken(request, response);
				return INVALID_RESULT;
			}
			
			if(token.isExpiringWithin(config.getRefreshInterval())) {
				LOG.fine(() -> format("Refreshing token for user %s created at %s.",
						  			  token.getUserId(),
						  			  isoDateFormat(token.getDateCreated())));
				
				// Fetch user again to apply recent roles to access token.
				// Throws an EntityNotFoundException, if the user does not exist!
				UserInfo user = userRegistry.getUserInfo(token.getUserId());
				if(user == null) {
					return INVALID_RESULT;
				}
				Date expiry = computeExpiryDate(user);
				JsonWebToken<Payload> renewedToken = newAccessToken(token)
										   			 .withUserId(user.getUserId())
										   			 .withRoles(user.getRoles())
										   			 .withDateExpiry(expiry)
										   			 .build();
				
				writeCookie(request, 
							response, 
							encoder.encode(renewedToken),
							(int)(expiry.getTime() - currentTimeMillis())/1000);
				
			}
			
			return new CredentialValidationResult(token.getUserId().toString(),
												  token.getRoles());
			
		} catch (JsonWebTokenSignatureException e) {
			LOG.log(FINER,e.getMessage(),e);
			return INVALID_RESULT;
		}		
	}

}
