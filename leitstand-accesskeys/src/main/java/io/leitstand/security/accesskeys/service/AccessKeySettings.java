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

/**
 * The <code>AccessKeySettings</code> value object contains the ID, name, description, creation date and scopes of an access key.
 */
public class AccessKeySettings extends AccessKeyInfo{

	/**
	 * Creates a builder for an <code>AccessKeySettings</code> object.
	 * @return a builder for an <code>AccessKeySettings</code> object.
	 */
	public static Builder newAccessKeySettings() {
		return new Builder();
	}
	
	/**
	 * Builder for an immutable <code>AccessKeySettings</code> value object.
	 */
	public static class Builder extends BaseAccessKeyInfoBuilder<AccessKeySettings, Builder>{
		
		protected Builder() {
			super(new AccessKeySettings());
		}
		
		/**
		 * Sets the access key scopes.
		 * @param scopes the access key scopes.
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withScopes(String... scopes) {
			return withScopes(asSet(scopes));
		}

		/**
		 * Sets the access key scopes.
		 * @param scopes the access key scopes.
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withScopes(Set<String> scopes) {
			assertNotInvalidated(getClass(), instance);
			instance.scopes = new TreeSet<>(scopes);
			return this;
		}
		
	}
	
	private SortedSet<String> scopes = emptySortedSet();
	
	/**
	 * Returns the access key scopes.
	 * @return the access key scopes.
	 */
	public SortedSet<String> getScopes() {
		return unmodifiableSortedSet(scopes);
	}
	

	
}
