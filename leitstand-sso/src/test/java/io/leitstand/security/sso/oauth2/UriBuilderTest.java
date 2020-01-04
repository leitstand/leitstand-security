/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class UriBuilderTest {

	
	@Test
	public void preserve_redirect_target_with_empty_query_string() {
		assertEquals("http://localhost:9080/foo/bar",
					  new UriBuilder("http://localhost:9080/foo/bar").toString());
	}
	
	@Test
	public void encode_redirect_target_query_string_with_a_single_parameter() {
		assertEquals("http://localhost:9080/foo/bar?filter=level%3A%3E5+AND+name%3A%22test+test%22",
					 new UriBuilder("http://localhost:9080/foo/bar?filter=level:>5 AND name:\"test test\"").toEncodedString());
	}
	
	@Test
	public void encode_redirect_target_query_string_with_multiple_parameter() {
		assertEquals("http://localhost:9080/foo/bar?filter=level%3A%3E5+AND+name%3A%22test+test%22&x=y",
				 	 new UriBuilder("http://localhost:9080/foo/bar?filter=level:>5 AND name:\"test test\"&x=y").toEncodedString());
	}
	
	@Test
	public void support_trailing_empty_parameter() throws Exception {
		UriBuilder uri = new UriBuilder("http://10.100.97.43:9080/search?rangetype=relative&relative=0&from=&to=&q=");
		
		assertEquals("relative",uri.getQueryParam("rangetype"));
		assertEquals("0",uri.getQueryParam("relative"));
		assertTrue(uri.getQueryParam("from").isEmpty());
		assertTrue(uri.getQueryParam("to").isEmpty());
		assertTrue(uri.getQueryParam("q").isEmpty());
	}
	
	
	@Test
	public void can_append_parameter() {
		assertEquals("http://localhost:9080/foo/bar?filter=test",
					 new UriBuilder("http://localhost:9080/foo/bar").addQueryParam("filter","test").toEncodedString());
		assertEquals("http://localhost:9080/foo/bar?filter=test&x=y",
				 	 new UriBuilder("http://localhost:9080/foo/bar?filter=test").addQueryParam("x","y").toEncodedString());
	}
	
}
