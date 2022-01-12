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
package io.leitstand.security.accesskeys.rs;

/**
 * Enumeration of the access token scopes protecting access-key management.
 */
public final class Scopes {
	
	/**
	 * The <code>adm</code> scope grants unrestricted access to access-key management.
	 */
	public static final String ADM = "adm";
	/**
	 * The <code>adm.read</code> scope grants read-only access to access-key management.
	 */
	public static final String ADM_READ = "adm.read";
	/**
	 * The <code>adm.accesskey</code> scope grants unrestricted access to access-key management.
	 */
	public static final String ADM_ACCESSKEY = "adm.accesskey";

	/**
	 * The <code>adm.accesskey.read</code> scope grants read-only access to access-key management.
	 */
	public static final String ADM_ACCESSKEY_READ = "adm.accesskey.read";
	
	private Scopes() {
		// No instances allowed
	}
}
