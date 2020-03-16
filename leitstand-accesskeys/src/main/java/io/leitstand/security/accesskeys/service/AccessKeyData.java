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
package io.leitstand.security.accesskeys.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static java.util.Collections.emptySortedSet;
import static java.util.Collections.unmodifiableSortedSet;

import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class AccessKeyData extends AccessKeyMetaData{

	public static Builder newAccessKey() {
		return new Builder();
	}
	
	public static class Builder extends MetaDataBuilder<AccessKeyData, Builder>{
		
		protected Builder() {
			super(new AccessKeyData());
		}
		
		public Builder withScopes(String... scopes) {
			return withScopes(asSet(scopes));
		}
		
		public Builder withScopes(Set<String> methods) {
			assertNotInvalidated(getClass(), instance);
			instance.scopes = new TreeSet<>(methods);
			return this;
		}
		
	}
	
	private SortedSet<String> scopes = emptySortedSet();
	

	public SortedSet<String> getScopes() {
		return unmodifiableSortedSet(scopes);
	}
	

	
}
