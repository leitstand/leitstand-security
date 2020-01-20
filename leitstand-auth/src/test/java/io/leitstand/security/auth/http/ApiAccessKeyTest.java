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
