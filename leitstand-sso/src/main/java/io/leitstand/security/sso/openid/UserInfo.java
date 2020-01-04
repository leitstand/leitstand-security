/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.openid;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.jsonb.UserIdAdapter;
import io.leitstand.security.users.service.EmailAddress;

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
		
		public Builder withSub(UserId name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.sub = name;
			return this;
		}
		
		public Builder withEmail(EmailAddress email) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.email = email;
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
	@JsonbTypeAdapter(UserIdAdapter.class)
	private UserId sub;
	private EmailAddress email;
	
	public String getName() {
		return name;
	}
	
	public UserId getSub() {
		return sub;
	}
	
	public EmailAddress getEmail() {
		return email;
	}
	
}
