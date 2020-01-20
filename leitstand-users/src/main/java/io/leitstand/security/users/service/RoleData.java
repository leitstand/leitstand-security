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
package io.leitstand.security.users.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import io.leitstand.commons.model.ValueObject;

public class RoleData extends ValueObject implements Comparable<RoleData>{
	
	public static Builder newRoleData() {
		return new Builder();
	}
	
	public static class Builder {
		private RoleData instance = new RoleData();
		
		public Builder withName(String name) {
			assertNotInvalidated(getClass(), instance);
			instance.name = name;
			return this;
		}

		public Builder withDescription(String description) {
			assertNotInvalidated(getClass(), instance);
			instance.description = description;
			return this;
		}
		
		public RoleData build() {
			try {
				assertNotInvalidated(getClass(),instance);
				return instance;
			} finally {
				this.instance = null;
			}
		}
	}
	
	private String name;
	private String description;
	
	public String getName() {
		return name;
	}
	
	public String getDescription() {
		return description;
	}
	
	@Override
	public int compareTo(RoleData o) {
		return name.compareTo(o.name);
	}
	
}
