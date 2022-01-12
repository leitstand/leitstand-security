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
package io.leitstand.security.sso.standalone.oauth2;

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
