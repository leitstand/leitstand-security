/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.user;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static java.util.Collections.emptySet;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserId;

public class UserInfo extends ValueObject{

	public static Builder newUserInfo() {
		return new Builder();
	}
	
	public static class Builder {
		private UserInfo userInfo = new UserInfo();
		
		public Builder withUserId(UserId userId) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.userId = userId;
			return this;
		}
		
		public Builder withRoles(String... roles) {
			return withRoles(asSet(roles));
		}
		
		public Builder withRoles(Set<String> roles) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.roles = roles;
			return this;
		}
		
		public Builder withAccessTokenTtl(Long duration, TimeUnit unit) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.accessTokenTtl = duration;
			userInfo.accessTokenTtlUnit = unit;
			return this;
		}
		
		public UserInfo build() {
			try {
				assertNotInvalidated(getClass(), userInfo);
				return userInfo;
			} finally {
				this.userInfo = null;
			}
		}
	}
	
	private UserId userId;
	private Set<String> roles = emptySet();
	private Long accessTokenTtl;
	private TimeUnit accessTokenTtlUnit;

	public UserId getUserId() {
		return userId;
	}
	
	public Set<String> getRoles() {
		return roles;
	}
	
	public Long getAccessTokenTtl() {
		return accessTokenTtl;
	}
	
	public TimeUnit getAccessTokenTtlUnit() {
		return accessTokenTtlUnit;
	}
	
}
