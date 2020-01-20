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

import io.leitstand.commons.model.Scalar;

/**
 * A helper to handle bearer token data.
 */
public class BearerToken extends Scalar<String>{


	private static final long serialVersionUID = 1L;

	/**
	 * Creates a <code>BasicAuthentication</code> instance from the specified <code>Authorization</code> header.
	 * @param header the HTTP <i>Authorization</i> header
	 * @return the <code>BasicAuthentication</code> instance, unless the specified <code>Authorization</code> header is <code>null</code> or did not convey HTTP Basic Authentication data.
	 * @throws IllegalArgumentException if the <i>Authorization</i> HTTP header does not convey HTTP Basic authentication data.
	 */
	public static BearerToken valueOf(Authorization header) {
		if(header == null) {
			return null;
		}
		return new BearerToken(header);
	}
	
	public static BearerToken bearerToken(String token) {
		return fromString(token,BearerToken::new);
	}
	
	private String value;
	
	public BearerToken(String token) {
		this.value = token;
	}
	
	/**
	 * Creates a <code>BearerToken</code> helper
	 * @param header the HTTP Authorization header.
	 * @throws IllegalArgumentException if the header does not convey HTTP Basic Authentication data
	 */
	public BearerToken(Authorization header) {
		if(!header.isBearerToken()) {
			throw new IllegalArgumentException("Bearer token authorization header expected!");
		}
		this.value = header.getCredentials();
	}
	
	@Override
	public String getValue() {
		return value;
	}
	
	@Override
	public String toString() {
		return "Bearer "+value;
	}

}
