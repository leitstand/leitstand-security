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

import static io.leitstand.commons.model.ObjectUtil.optional;
import static io.leitstand.security.auth.ReasonCode.AUT0001E_UNAUTHENTICATED_ACCESS_DENIED;
import static io.leitstand.security.auth.ReasonCode.AUT0002E_SCOPE_ACCESS_DENIED;
import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.joining;

import java.lang.reflect.Method;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.rs.Authenticated;
import io.leitstand.commons.rs.Public;
import io.leitstand.security.auth.Scopes;
import io.leitstand.security.auth.UserContext;

@Authenticated
@Interceptor
@Dependent
public class ScopeAuthenticated {
	
	private UserContext user;
	
	protected ScopeAuthenticated() {
		// CDI
	}
	
	@Inject
	protected ScopeAuthenticated(UserContext user) {
		this.user = user;
	}
	
	@AroundInvoke
	public Object authenticate(InvocationContext context) throws Exception{
		
		Method method = context.getMethod();
		Class<?> clazz = method.getDeclaringClass();
		// Everyone can access a public resource
		if(clazz.isAnnotationPresent(Public.class) || method.isAnnotationPresent(Public.class)) {
			return context.proceed();
		}
		
		// Unauthenticated users cannot access non-public resources
		if(user.isUnauthenticated()) {
			throw new AccessDeniedException(AUT0001E_UNAUTHENTICATED_ACCESS_DENIED);
		}
		
		Scopes methodScopes = method.getAnnotation(Scopes.class);
		Scopes classScopes = method.getDeclaringClass().getAnnotation(Scopes.class);
		
		// A resource without scope assignments can be accessed by all authenticated users.
		if(methodScopes == null && classScopes == null) {
			return context.proceed();
		}
		
		// Grant access if the user is allowed to access any of the declared method scopes.
		if(methodScopes != null && user.scopesIncludeOneOf(methodScopes.value())) {
			return context.proceed();
		}
		// Grant access  if user is allowed to access any of the declared resource scopes.
		if(classScopes != null && user.scopesIncludeOneOf(classScopes.value())) {
			return context.proceed();
		}
		
		// Deny access and provide a summary about allowed scopes.
		SortedSet<String> scopesAllowed = new TreeSet<>();
		scopesAllowed.addAll(optional(methodScopes, s -> asList(s.value()), emptySet()));
		scopesAllowed.addAll(optional(classScopes,s -> asList(s.value()),emptySet()));
		
		
		throw new AccessDeniedException(AUT0002E_SCOPE_ACCESS_DENIED,
										user.getUserName(),
										scopesAllowed.stream()
										.collect(joining(", ")));
		
	}
	
	
}
