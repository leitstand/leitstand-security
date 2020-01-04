/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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
