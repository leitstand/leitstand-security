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
import static io.leitstand.security.users.service.RoleId.randomRoleId;
import static java.util.Collections.emptySortedSet;
import static java.util.Collections.unmodifiableSortedSet;

import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import io.leitstand.commons.model.ValueObject;

public class RoleSettings extends ValueObject implements Comparable<RoleSettings>{
	
	public static Builder newRoleSettings() {
		return new Builder();
	}
	
	public static class Builder {
		private RoleSettings instance = new RoleSettings();

		public Builder withRoleId(RoleId roleId) {
			assertNotInvalidated(getClass(), instance);
			instance.roleId = roleId;
			return this;
		}

		
		public Builder withRoleName(RoleName name) {
			assertNotInvalidated(getClass(), instance);
			instance.roleName = name;
			return this;
		}
		
		public Builder withSystemRole(boolean systemRole) {
			assertNotInvalidated(getClass(),instance);
			instance.systemRole = systemRole;
			return this;
		}

		public Builder withDescription(String description) {
			assertNotInvalidated(getClass(), instance);
			instance.description = description;
			return this;
		}
		
		public Builder withScopes(Set<String> scopes) {
			assertNotInvalidated(getClass(),instance);
			instance.scopes = new TreeSet<>(scopes);
			return this;
		}
		
		public RoleSettings build() {
			try {
				assertNotInvalidated(getClass(),instance);
				return instance;
			} finally {
				this.instance = null;
			}
		}
	}
	
	private RoleId roleId = randomRoleId();
	private RoleName roleName;
	private String description;
	private SortedSet<String> scopes = emptySortedSet();
	private boolean systemRole;
	
	public RoleId getRoleId() {
		return roleId;
	}
	
	public RoleName getRoleName() {
		return roleName;
	}
	
	public String getDescription() {
		return description;
	}
	
	@Override
	public int compareTo(RoleSettings o) {
		return roleName.compareTo(o.roleName);
	}
	
	public SortedSet<String> getScopes() {
		return unmodifiableSortedSet(scopes);
	}

	public boolean isSystemRole() {
		return systemRole;
	}
	
}
