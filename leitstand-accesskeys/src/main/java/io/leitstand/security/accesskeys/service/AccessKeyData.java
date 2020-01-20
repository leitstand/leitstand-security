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
import static java.util.Arrays.asList;
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
		
		public Builder withPaths(String... paths) {
			return withPaths(new TreeSet<>(asList(paths)));
		}
		
		public Builder withPaths(Set<String> paths) {
			assertNotInvalidated(getClass(), instance);
			instance.paths = new TreeSet<>(paths);
			return this;
		}
		
		public Builder withMethods(String... methods) {
			return withMethods(new TreeSet<>(asList(methods)));
		}
		
		public Builder withMethods(Set<String> methods) {
			assertNotInvalidated(getClass(), instance);
			instance.methods = new TreeSet<>(methods);
			return this;
		}
		
	}
	
	private SortedSet<String> paths = emptySortedSet();
	private SortedSet<String> methods = emptySortedSet();	
	
	public SortedSet<String> getPaths() {
		return unmodifiableSortedSet(paths);
	}
	
	public SortedSet<String> getMethods() {
		return unmodifiableSortedSet(methods);
	}
	

	
}
