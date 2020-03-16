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
package io.leitstand.security.sso.oidc;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import javax.json.bind.annotation.JsonbProperty;

import io.leitstand.commons.model.StringUtil;

public class AccessToken {
	
	@JsonbProperty("iat")
	private long dateCreated;
	@JsonbProperty("exp")
	private long dateExpiry;
	private String sub;
	private String scope;
	private OidcUserInfo userInfo;
	
	
	public Date getDateCreated() {
		return new Date(dateCreated);
	}
	
	public Date getDateExpiry() {
		return new Date(dateExpiry);
	}
	
	public boolean isExpired() {
		return System.currentTimeMillis() > dateExpiry;
	}
	
	public String getSub() {
		return sub;
	}
	
	public Set<String> getScopes(){
		if(StringUtil.isEmptyString(scope)) {
			return emptySet();
		}
		return new TreeSet<>(asList(scope.split("\\s")));
		
	}
	
	public OidcUserInfo getUserInfo() {
		return userInfo;
	}
}
