/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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
		when(request.getRequestURI()).thenReturn("/api/v1/_login");
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
		when(cookie.getName()).thenReturn("rtb-access");
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
