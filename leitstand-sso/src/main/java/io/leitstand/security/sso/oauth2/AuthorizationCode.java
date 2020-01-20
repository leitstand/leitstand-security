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
package io.leitstand.security.sso.oauth2;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import java.util.Date;

import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.jsonb.DateToLongAdapter;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jwt.JsonWebToken;

/**
 * The authorization code to grant access to the user resource.
 * <p>
 * The authorization code is implemented as JSON Web Token.
 * It conveys the following information:
 * <ul>
 *  <li><i>clientId</i> the system (client in the OAuth terminology) for which this authorization code was created.</li>
 * 	<li><i>userName</i> the login name of the authenticated user
 *  <li><i>dateCreated</i> the timestamp when the authorization code was created</li>
 * </ul>
 */
public class AuthorizationCode extends JsonWebToken<AuthorizationCode.Payload>{

	/**
	 * Returns a builder to create an immutable <code>AuthorizationCode</code> instance.
	 * @return a builder to create an immutable <code>AuhtorizationCode</code> instance.
	 */
	public static Builder newAuthorizationCode() {
		return new Builder();
	}
	
	/**
	 * The builder to create an immutable <code>AuthorizationCode</code> instance.
	 */
	public static class Builder {
		
		private Payload payload = new Payload();
		
		/**
		 * Sets the user id.
		 * @param userName the user login name
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withUserName(UserName userName) {
			assertNotInvalidated(getClass(), payload);
			payload.userName = userName;
			return this;
		}
		
		/**
		 * Sets the client id.
		 * @param clientId the system this authorization code is created for
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withClientId(String clientId) {
			assertNotInvalidated(getClass(),payload);
			payload.clientId = clientId;
			return this;
		}
		
		/**
		 * Returns the immutable <code>AuthorizationCode</code> instance and invalidates this builder.
		 * The builder must not be used after calling the <code>build()</code> method.
		 * All further invocation of this builder results in an exception.
		 * @return the <code>AuthorizationCode</code>.
		 */
		public AuthorizationCode build() {
			try {
				assertNotInvalidated(getClass(), payload);
				payload.dateCreated = new Date();
				return new AuthorizationCode(payload);
			} finally {
				this.payload = null;
			}
		}

	}
	
	/**
	 * The authorization code payload.
	 */
	public static class Payload{
		
		@JsonbProperty("sub")
		private UserName userName;
		@JsonbProperty("aud")
		private String clientId;
		@JsonbProperty("iat")
		@JsonbTypeAdapter(DateToLongAdapter.class)
		private Date dateCreated;
		
		/**
		 * Returns the user ID of the authenticated user.
		 * @return the user ID of the authenticated user.
		 */
		public UserName getUserName() {
			return userName;
		}
		
		/**
		 * Returns the client ID, i.e. the ID of the system this authorization code is created for.
		 * @return the client ID
		 */
		public String getClientId() {
			return clientId;
		}
		
		/**
		 * Returns the creation timestamp of this authorization code.
		 * @return the creation timestamp.
		 */
		public Date getDateCreated() {
			return new Date(dateCreated.getTime());
		}
		
	}
	
	/**
	 * Creates an new <code>AuthorizationCode</code> JWT.
	 * @param payload the JWT payload
	 */
	protected AuthorizationCode(Payload payload) {
		super(payload);
	}
	
	/**
	 * Returns the user name of the authenticated user.
	 * @return the user name of the authenticated user.
	 */
	public UserName getUserName() {
		return getPayload().getUserName();
	}
	
	/**
	 * Returns the client ID, i.e. the ID of the system this authorization code is created for.
	 * @return the client ID
	 */
	public String getClientId() {
		return getPayload().getClientId();
	}
	
	/**
	 * Returns the creation timestamp of this authorization code.
	 * @return the creation timestamp.
	 */
	public Date getDateCreated() {
		return getPayload().getDateCreated();
	}

}
