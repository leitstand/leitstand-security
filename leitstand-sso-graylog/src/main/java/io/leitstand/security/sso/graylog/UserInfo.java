/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.graylog;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.Set;
import java.util.TreeSet;

import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.jsonb.UserIdAdapter;

public class UserInfo extends ValueObject{

	public static Builder newUserInfo() {
		return new Builder();
	}
	
	public static class Builder {
		private UserInfo userInfo = new UserInfo();
		
		public Builder withName(String name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.name = name;
			return this;
		}

		public Builder withSurname(String name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.surname = name;
			return this;
		}
		
		public Builder withUsername(UserId name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.username = name;
			return this;
		}
		
		public Builder withEmail(String email) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.email = email;
			return this;
		}
		
		public Builder withRoles(Set<String> roles) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.roles = unmodifiableSet(new TreeSet<>(roles));
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
	
	private String name;
	private String surname;
	@JsonbTypeAdapter(UserIdAdapter.class)
	private UserId username;
	private String email;
	@JsonbProperty("role_ids")
	private Set<String> roles = emptySet();
	//Graylog requires that groups must not be null. Hence we use an empty groups.
	private Set<String> groups = emptySet();
	
	public String getName() {
		return name;
	}
	
	public String getSurname() {
		return surname;
	}
	public UserId getUsername() {
		return username;
	}
	
	public String getEmail() {
		return email;
	}
	public Set<String> getRoles() {
		return roles;
	}
	
	public Set<String> getGroups() {
		return groups;
	}
	
}
