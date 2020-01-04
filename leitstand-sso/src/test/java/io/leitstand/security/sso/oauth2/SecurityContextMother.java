/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oauth2;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.Principal;

import javax.ws.rs.core.SecurityContext;

public final class SecurityContextMother {

	public static SecurityContext unauthenticated() {
		return mock(SecurityContext.class);
	}
	
	public static SecurityContext authenticatedAs(String userId) {
		Principal authenticated = mock(Principal.class);
		when(authenticated.getName()).thenReturn(userId);
		SecurityContext ctx = mock(SecurityContext.class);
		when(ctx.getUserPrincipal()).thenReturn(authenticated);
		return ctx;
	}
	
	private SecurityContextMother() {
		// No instances allowed
	}
}
