/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import io.leitstand.security.auth.accesskey.ApiAccessKey;

public class ApiAccessKeyTest {


	@Test
	public void accept_all_path_if_paths_is_empty() {
		ApiAccessKey key = newApiAccessKey().build();
		assertTrue(key.isPathAllowed("/foo"));
		assertTrue(key.isPathAllowed("/bar"));
	}
	
	@Test
	public void reject_paths_not_in_path_list() {
		ApiAccessKey key = newApiAccessKey().withPaths("/foo").build();
		assertTrue(key.isPathAllowed("/foo"));
		assertFalse(key.isPathAllowed("/bar"));
	}
	
	@Test
	public void accept_all_method_if_method_list_is_empty() {
		ApiAccessKey key = newApiAccessKey().build();
		assertTrue(key.isMethodAllowed("get"));
		assertTrue(key.isMethodAllowed("GET"));
		assertTrue(key.isMethodAllowed("post"));
	}
	
	@Test
	public void accept_method_in_method_list() {
		ApiAccessKey key = newApiAccessKey().withMethods("get").build();
		assertTrue(key.isMethodAllowed("get"));
		assertTrue(key.isMethodAllowed("GET"));
		assertFalse(key.isMethodAllowed("post"));
	}
	
	
	
}
