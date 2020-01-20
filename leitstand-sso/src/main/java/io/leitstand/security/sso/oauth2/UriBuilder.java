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
package io.leitstand.security.sso.oauth2;

import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static java.util.function.Function.identity;

import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * A utility to create a well-encoded redirect URI
 */
class UriBuilder {
	
	private static final String encode(String s) {
		try {
			return URLEncoder.encode(s,"UTF-8");
		} catch (UnsupportedEncodingException e) {
			// UTF-8 support is mandatory for all JVM.
			// Thus this error should never occur!
			throw new UncheckedIOException(e);
		}
	}

	private Map<String,String> queryParams;
	private String target;
	
	UriBuilder(String redirectUri){
		this.queryParams = new LinkedHashMap<>();
		int qm = redirectUri.indexOf('?');
		if(qm < 0) {
			target = redirectUri;
		} else {
			target = redirectUri.substring(0,qm);
			String[] tokens = redirectUri.substring(qm+1).split("&|=");
			int i = 0;
			// If the last query parameter is empty, i.e. the query string ends with =,
			// then a odd number of tokens is returned and the last empty string for the last 
			// parameter is missing, which would create an IndexOutOfBoundsException when attempting to
			// read the value.
			int n = (tokens.length % 2 == 0 ? tokens.length : tokens.length - 1);
			for(; i < n ; i++) {
				String name = tokens[i];
				String value = tokens[++i];
				queryParams.put(name,value);
			}
			if(i < tokens.length) {
				// Add the last empty parameter
				queryParams.put(tokens[i],"");
			}
		}
	}
	
	UriBuilder addQueryParam(String name, String value) {
		queryParams.put(name,value);
		return this;
	}
	
	String getQueryParam(String name) {
		return queryParams.get(name);
	}
	
	boolean containsQueryParam(String name) {
		return isNonEmptyString(getQueryParam(name));
	}
	
	@Override
	public String toString() {
		return toString(identity());
	}
	
	URI toUri() {
		return URI.create(toEncodedString());
	}
	
	String toEncodedString() {
		return toString(UriBuilder::encode);
	}
	
	private String toString(Function<String,String> encoder) {
		StringBuilder buffer = new StringBuilder(target);
		String del = "?";
		for(Map.Entry<String,String> param : queryParams.entrySet()) {
			buffer.append(del)
				  .append(param.getKey())
				  .append("=")
				  .append(encoder.apply(param.getValue()));
			del = "&";
		}
		return buffer.toString();
	}
	
}
