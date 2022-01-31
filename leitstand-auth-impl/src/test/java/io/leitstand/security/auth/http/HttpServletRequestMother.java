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
package io.leitstand.security.auth.http;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Locale;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public final class HttpServletRequestMother {

	public static HttpServletRequest loginRequest() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURI()).thenReturn("/api/v1/login");
		when(request.getMethod()).thenReturn("POST");
		return request;
	}
	
	public static HttpServletRequest basicAuthenticationRequest() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURI()).thenReturn("/api/v1/foo/bar");
		when(request.getMethod()).thenReturn("POST");
		when(request.getHeader("Authorization")).thenReturn("Basic CREDENTIALS");
		return request;
	}
	
	public static HttpServletRequest bearerAuthenticationRequest() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURI()).thenReturn("/api/v1/foo/bar");
		when(request.getMethod()).thenReturn("POST");
		when(request.getHeader("Authorization")).thenReturn("Bearer CREDENTIALS");
		return request;
	}
	
	public static HttpServletRequest cookieAuthenticationRequest() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURI()).thenReturn("/api/v1/foo/bar");
		when(request.getMethod()).thenReturn("POST");
		Cookie cookie = mock(Cookie.class);
		when(cookie.getName()).thenReturn("LEITSTAND_ACCESS");
		when(cookie.getValue()).thenReturn("TOKEN");
		Locale.setDefault(Locale.US);
		when(request.getCookies()).thenReturn(new Cookie[] {cookie});
		return request;
	}
	
	public static HttpServletRequest staticResourceRequest() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRequestURI()).thenReturn("/static/resource");
		when(request.getMethod()).thenReturn("GET");
		return request;
	}

	
	private HttpServletRequestMother() {
		// No instances allowed
	}
}
