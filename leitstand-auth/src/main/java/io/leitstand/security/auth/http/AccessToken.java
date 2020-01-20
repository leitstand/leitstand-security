/*
 * (c) RtBrick, Inc All rights reserved, 2015 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static java.lang.System.currentTimeMillis;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;
import static java.util.UUID.randomUUID;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.jsonb.DateToLongAdapter;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.jwt.JsonWebToken;

/**
 * The <code>AccessToken</code> created after a successful login to authenticate subsequent requests of the authenticated user.
 * <p>
 * The access token is a {@link JsonWebToken} and created by the {@link LeitstandHttpAuthMechanism} after a successful login attempt.
 * The access token is stored in the <code>rtb-access</code> HttpOnly session cookie in order to be submitted by the browser with every request automatically.
 * @see ApiAccessKey
 */
public class AccessToken extends JsonWebToken<AccessToken.Payload> {
	
	/**
	 * Returns a builder to create a new immutable access token.
	 * @return the builder to create a new immutable access token.
	 */
	public static Builder newAccessToken() {
		return new Builder();
	}
	
	/**
	 * Returns a builder to create a new immutable access token and copies the value of the given template token to the new token.
	 * This facilitates refreshing access tokens. 
	 * @param template the access token used as template for the new access token.
	 * @return a new access token with the same values as the template token but a new issuing date
	 */
	public static Builder newAccessToken(JsonWebToken<Payload> template) {
		Builder builder = new Builder();
		builder.payload.userName = template.getPayload().getUserName();
		builder.payload.roles = new TreeSet<>(template.getPayload().getRoles());
		return builder;
	}
	
	/**
	 * The builder to create an immutable access token.
	 * This builder is invalidated after calling the {@link #build()} method
	 * and must not be used after the invocation of the build method.
	 */
	public static class Builder {
		
		private Payload payload = new Payload();
		
		/**
		 * Sets the user ID of the authenticated user.
		 * @param userName the user name
		 * @return a reference to this builder to continue token creation
		 */
		public Builder withUserName(UserName userName) {
			assertNotInvalidated(getClass(),  payload);
			payload.userName = userName;
			return this;
		}
		
		/**
		 * Sets the roles of the authenticated user.
		 * @param roles the roles of the authenticated user.
		 * @return a reference to this builder to continue token creation.
		 */
		public Builder withRoles(String... roles) {
			return withRoles(asSet(roles));
		}
		
		/**
		 * Sets the roles of the authenticated user.
		 * @param roles the roles of the authenticated user.
		 * @return a reference to this builder to continue token creation.
		 */		
		public Builder withRoles(Set<String> roles) {
			assertNotInvalidated(getClass(),  payload);
			payload.roles = unmodifiableSet(roles);
			return this;
		}
		
		
		/**
		 * Sets the token expiry timestamp.
		 * @param dateExpiry the expiration timestamp
		 */		
		public Builder withDateExpiry(Date expiry) {
			assertNotInvalidated(getClass(),  payload);
			payload.dateExpiry = new Date(expiry.getTime());
			return this;
		}
		
		/**
		 * Creates the immutable access token and invalidates this builder. Subsequent invocation
		 * of any method of this builder cause an exception.
		 * @return the initialized token.
		 */
		public AccessToken build() {
			try {
				assertNotInvalidated(getClass(), payload);
				payload.dateCreated = new Date();
				return new AccessToken(payload);
			} finally {
				this.payload = null;
			}
		}
		
	}
	
	/**
	 * The payload of the access token.
	 */
	public static class Payload {
		
		// NOTE: Use JWT standard and public claims only to avoid name collision issues.
		   
		@JsonbProperty("jti")
		private String id = randomUUID().toString();
		
		@JsonbProperty("sub")
		private UserName userName;
		
		@JsonbProperty("iat")
		@JsonbTypeAdapter(DateToLongAdapter.class)
		private Date dateCreated;
		
		@JsonbProperty("exp")
		@JsonbTypeAdapter(DateToLongAdapter.class)
		private Date dateExpiry;
		
		
		@JsonbProperty("http://rtbrick.com:roles")
		private Set<String> roles = emptySet();
		
		
		/**
		 * Returns the unique JWT ID in UUIDv4 format.
		 * @return the unique JWT ID
		 */
		public String getId() {
			return id;
		}
		
		/**
		 * Returns the user name of the authenticated user.
		 * @return the user name of the authenticated user.
		 */
		public UserName getUserName() {
			return userName;
		}
		
		/**
		 * Returns the access token creation timestamp.
		 * @return the access token creation timestamp.
		 */
		public Date getDateCreated() {
			return new Date(dateCreated.getTime());
		}
		
		public Date getDateExpiry() {
			if(dateExpiry == null) {
				return null;
			}
			return new Date(dateExpiry.getTime());
		}
		
		public boolean isExpired() {
			return dateExpiry != null && dateExpiry.getTime() < currentTimeMillis();
		}
		
		/**
		 * Returns the roles of the authenticated user.
		 * @return an immutable set of the authenticated user's roles.
		 */
		public Set<String> getRoles() {
			return unmodifiableSet(roles);
		}
		
	}
	
	/**
	 * Creates an <code>AccessToken</code>.
	 * @param payload the access token payload
	 */
	protected AccessToken(Payload payload) {
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
	 * Returns the creation timestamp of the access token.
	 * @return the creation timestamp of the access token.
	 */
	@Override
	public Date getDateCreated() {
		return getPayload().getDateCreated();
	}
	
	/**
	 * Returns the expiration timestamp of the access token.
	 * @return the expiration timestamp of the access token.
	 */
	@Override
	public Date getDateExpiry() {
		return getPayload().getDateExpiry();
	}
	
	/**
	 * Checks whether a user has the given role.
	 * @param role the role the user shall be tested for
	 * @return <code>true</code> if the user has the given role, <code>false</code> otherwise.
	 */
	public boolean isUserInRole(String role) {
		return getPayload().getRoles().contains(role);
	}

	/**
	 * Returns an immutable set of roles of the authenticated user.
	 * @return the roles of the authenticated user.
	 */
	public Set<String> getRoles() {
		return getPayload().getRoles();
	}

}