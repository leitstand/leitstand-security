/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.security.auth.http.HttpServletRequestMother.basicAuthenticationRequest;
import static io.leitstand.security.auth.http.HttpServletRequestMother.loginRequest;
import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;
import static javax.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static javax.security.enterprise.AuthenticationStatus.SUCCESS;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.util.Set;

import javax.enterprise.inject.Instance;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.user.LoginManager;

@RunWith(MockitoJUnitRunner.class)
public class LeitstandHttpAuthMechanismTest {
	
	private static final CredentialValidationResult VALID_CREDENTIALS = new CredentialValidationResult("junit");

	@Mock
	private Instance<AccessTokenManager> accessTokenManagers;
	
	@Mock
	private AccessTokenManager noopAccessTokenManager;

	@Mock
	private AccessTokenManager accessTokenManager;

	@Mock
	private AccessTokenManager neverCalledTokenManager;
	
	@Mock
	private LoginManager loginManager;
	
	@InjectMocks
	private LeitstandHttpAuthMechanism auth = new LeitstandHttpAuthMechanism();
	
	private HttpServletResponse response;
	private HttpMessageContext context;
	
	@Before
	public void freshResponseAndContext() {
		response = mock(HttpServletResponse.class);
		context  = mock(HttpMessageContext.class);
		when(context.notifyContainerAboutLogin(VALID_CREDENTIALS)).thenReturn(SUCCESS);
		when(context.notifyContainerAboutLogin(INVALID_RESULT)).thenReturn(SEND_FAILURE);
		when(accessTokenManagers.iterator()).thenReturn(asList(noopAccessTokenManager,accessTokenManager,neverCalledTokenManager).iterator());
		when(noopAccessTokenManager.validateAccessToken(any(HttpServletRequest.class), any(HttpServletResponse.class))).thenReturn(NOT_VALIDATED_RESULT);
	
	}
	
	
	@Test
	public void issues_access_token_after_successful_login() throws AuthenticationException {
		
		HttpServletRequest request = loginRequest();
		when(loginManager.login(request, response)).thenReturn(VALID_CREDENTIALS);
		when(accessTokenManager.issueAccessToken(eq(request), 
												 eq(response), 
												 any(UserId.class),
												 any(Set.class))).thenReturn(TRUE);
		AuthenticationStatus status = auth.validateRequest(request, 
									  response, 
									  context);
		assertEquals(SUCCESS, status);
		verify(context).notifyContainerAboutLogin(VALID_CREDENTIALS);
		verify(noopAccessTokenManager).issueAccessToken(request, 
														response, 
														UserId.valueOf(VALID_CREDENTIALS.getCallerPrincipal()),
														VALID_CREDENTIALS.getCallerGroups());
		verify(accessTokenManager).issueAccessToken(request, 
													response, 
													UserId.valueOf(VALID_CREDENTIALS.getCallerPrincipal()),
													VALID_CREDENTIALS.getCallerGroups());
	}
	
	@Test
	public void do_not_issue_access_token_after_failed_login() throws AuthenticationException {
		
		HttpServletRequest request = loginRequest();
		when(loginManager.login(request, response)).thenReturn(INVALID_RESULT);
		
		AuthenticationStatus status = auth.validateRequest(request, 
						  	 							   response, 
						  	 							   context);
		
		assertEquals(SEND_FAILURE,status);
		verify(response).setStatus(SC_UNAUTHORIZED);
		verifyZeroInteractions(context,
							   noopAccessTokenManager,
							   accessTokenManager,
							   neverCalledTokenManager);
		
	}
	
	@Test
	public void grant_access_for_valid_access_token() throws AuthenticationException{
		
		HttpServletRequest request = basicAuthenticationRequest();
		when(accessTokenManager.validateAccessToken(request, response)).thenReturn(VALID_CREDENTIALS);
		
		AuthenticationStatus status = auth.validateRequest(request, 
						  	 							   response, 
						  	 							   context);
		verify(context).notifyContainerAboutLogin(VALID_CREDENTIALS);
		assertEquals(SUCCESS,status);
		verify(noopAccessTokenManager,never()).issueAccessToken(eq(request),
															    eq(response),
															    any(UserId.class),
															    any(Set.class));
		verify(accessTokenManager,never()).issueAccessToken(eq(request),
			    											eq(response),
			    											any(UserId.class),
			    											any(Set.class));
	}
	
	@Test
	public void deny_access_for_invalid_credentials()throws AuthenticationException {
		HttpServletRequest request = basicAuthenticationRequest();
		Authorization authHeader = Authorization.valueOf(request.getHeader("Authorization"));
		when(accessTokenManager.validateAccessToken(request, response)).thenReturn(INVALID_RESULT);
		
		AuthenticationStatus status = auth.validateRequest(request, 
						  	 							   response, 
						  	 							   context);
		assertEquals(SEND_FAILURE,status);
		verify(response).setStatus(SC_UNAUTHORIZED);
		verify(noopAccessTokenManager,never()).issueAccessToken(eq(request),
																eq(response),
																any(UserId.class),
																any(Set.class));
		verify(accessTokenManager,never()).issueAccessToken(eq(request),
															eq(response),
															any(UserId.class),
															any(Set.class));
	}
	
	@After
	public void never_invoked_never_called_access_token_manager() {
		verifyZeroInteractions(neverCalledTokenManager);
	}
	
}
