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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import io.leitstand.security.sso.standalone.oauth2.UriBuilder;

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
