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
package io.leitstand.security.auth.scope;

import static io.leitstand.security.auth.ReasonCode.AUT0001E_UNAUTHENTICATED_ACCESS_DENIED;
import static io.leitstand.security.auth.ReasonCode.AUT0002E_SCOPE_ACCESS_DENIED;
import static io.leitstand.security.auth.scope.InvocationContextMother.invoke;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.reason;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import javax.interceptor.InvocationContext;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.rs.Public;
import io.leitstand.security.auth.Scopes;
import io.leitstand.security.auth.UserContext;

@RunWith(MockitoJUnitRunner.class)
public class ScopeAuthenticatorTest {
	
	@Rule
	public ExpectedException exception = ExpectedException.none();
	
	@Scopes("default")
	static final class ProtectedResource {
		
		@Scopes("specific")
		public void specificScope() {
			
		}
		
		public void resourceScope() {
		
		}
		
		@Public
		public void everyone() {
		    
		}
	}
	
	// A resource without scopes and not declared as being public 
	// can be accessed by all authenticated users.
	static final class UnprotectedResource {
		
		public void foo() {
			
		}
	}
	
	// A public resource is accessible without authentication.
	@Public
	static final class PublicResource {
		
		public void foo() {
			
		}
	}
	
	@Mock
	private UserContext userContext;
	
	@InjectMocks
	private ScopeAuthenticated authenticator = new ScopeAuthenticated();
	
	@Test
	public void unauthenticated_can_access_public_resource() throws Exception{
		InvocationContext context = invoke(PublicResource.class, "foo");
		authenticator.authenticate(context);
		
		verify(context).proceed();
		verifyZeroInteractions(userContext);
	}
	
	@Test
    public void unauthenticated_can_access_public_resource_method() throws Exception{
        InvocationContext context = invoke(ProtectedResource.class, "everyone");
        authenticator.authenticate(context);
        
        verify(context).proceed();
        verifyZeroInteractions(userContext);
    }
	
	@Test
	public void unauthentication_cannot_access_unprotected_resource() throws Exception {
		exception.expect(AccessDeniedException.class);
		exception.expect(reason(AUT0001E_UNAUTHENTICATED_ACCESS_DENIED));
		
		InvocationContext context = invoke(UnprotectedResource.class, "foo");
		when(userContext.isUnauthenticated()).thenReturn(true);
		
		authenticator.authenticate(context);
		
		verify(context,never()).proceed();
	}
	
	@Test
	public void authenticated_user_cannot_access_protected_resource_when_scope_is_not_included() throws Exception {
		exception.expect(AccessDeniedException.class);
		exception.expect(reason(AUT0002E_SCOPE_ACCESS_DENIED));
		
		InvocationContext context = invoke(ProtectedResource.class, "resourceScope");
		
		authenticator.authenticate(context);
		
		verify(context,never()).proceed();
		verify(userContext).isUnauthenticated();
		verify(userContext).scopesIncludeOneOf("default");
	}
	
	@Test
	public void authenticated_can_access_protected_resource_when_scope_included() throws Exception {
		
		InvocationContext context = invoke(ProtectedResource.class, "specificScope");
		when(userContext.scopesIncludeOneOf("specific")).thenReturn(true);
		authenticator.authenticate(context);
		
		verify(context).proceed();
		verify(userContext).isUnauthenticated();
	}
	
	
	@Test
	public void class_and_method_scopes_are_cumulative() throws Exception {
		
		InvocationContext context = invoke(ProtectedResource.class, "specificScope");
		when(userContext.scopesIncludeOneOf("default")).thenReturn(true);
		authenticator.authenticate(context);
		
		verify(context).proceed();
		verify(userContext).isUnauthenticated();
	}

	
	@Test
	public void authenticated_can_access_unprotected() throws Exception {
		
		InvocationContext context = invoke(UnprotectedResource.class, "foo");
		
		authenticator.authenticate(context);
		
		verify(context).proceed();
	}

	
}
