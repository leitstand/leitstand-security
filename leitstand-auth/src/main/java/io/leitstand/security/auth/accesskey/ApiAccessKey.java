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
package io.leitstand.security.auth.accesskey;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.jsonb.DateToLongAdapter;
import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.http.LeitstandHttpAuthMechanism;
import io.leitstand.security.auth.jwt.JsonWebToken;

/**
 * The <code>AccessToken</code> created after a successful login to authenticate subsequent requests of the authenticated user.
 * <p>
 * The access token is a {@link JsonWebToken} and created by the {@link LeitstandHttpAuthMechanism} after a successful login attempt.
 * The access token is stored in the <code>rtb-access</code> HttpOnly session cookie in order to be submitted by the browser with every request automatically.
 * @see ApiAccessKey
 */
public class ApiAccessKey extends JsonWebToken<ApiAccessKey.Payload> {
	
	private static final ConcurrentMap<String,Pattern> PATTERNS = new ConcurrentHashMap<>();
	
	/**
	 * Returns a builder to create a new immutable access token.
	 * @return the builder to create a new immutable access token.
	 */
	public static Builder newApiAccessKey() {
		return new Builder();
	}
	
	/**
	 * Returns a builder to create a new immutable access token and copies the value of the given template token to the new token.
	 * This facilitates refreshing access tokens. 
	 * @param template - the access token used as template for the new access token.
	 * @return a new access token with the same values as the template token but a new issuing date
	 */
	public static Builder newApiAccessKey(ApiAccessKey template) {
		Builder builder = new Builder();
		builder.payload.userName = template.getPayload().getUserName();
		return builder;
	}
	
	/**
	 * The builder to create an immutable access token.
	 * This builder is invalidated after calling the {@link #build()} method
	 * and must not be used after the invocation of the build method.
	 */
	public static class Builder {
		
		private Payload payload = new Payload();
		
		public Builder withId(AccessKeyId accessKeyId) {
			assertNotInvalidated(getClass(), payload);
			payload.id = accessKeyId;
			return this;
		}
		
		/**
		 * Sets the user name of the authenticated user.
		 * @param userName the user name
		 * @return a reference to this builder to continue token creation
		 */
		public Builder withUserName(UserName userName) {
			assertNotInvalidated(getClass(),  payload);
			payload.userName = userName;
			return this;
		}
		
		public Builder withMethods(String... methods) {
			return withMethods(new TreeSet<String>(asList(methods)));
		}
		
		public Builder withMethods(Set<String> methods) {
			assertNotInvalidated(getClass(), payload);
			payload.methods = new TreeSet<>();
			for(String method : methods) {
				payload.methods.add(method.toLowerCase());
			}
			return this;
		}
		
		public Builder withPaths(String... paths) {
			assertNotInvalidated(getClass(), payload);
			payload.paths = new TreeSet<>(asList(paths));
			return this;
		}
		
		public Builder withPaths(Set<String> paths) {
			assertNotInvalidated(getClass(), payload);
			payload.paths = new TreeSet<>(paths);
			return this;
		}
		
		public Builder withDateCreated(Date dateCreated) {
			assertNotInvalidated(getClass(), payload);
			payload.dateCreated = new Date(dateCreated.getTime());
			return this;
		}
		
		public Builder withTemporaryAccess(boolean temporaryAccess) {
			assertNotInvalidated(getClass(), payload);
			payload.temporaryAccess = temporaryAccess;
			return this;
		}
		
		/**
		 * Creates the immutable access token and invalidates this builder. Subsequent invocation
		 * of any method of this builder cause an exception.
		 * @return the initialized token.
		 */
		public ApiAccessKey build() {
			try {
				assertNotInvalidated(getClass(), payload);
				if(payload.dateCreated == null) {
					payload.dateCreated = new Date();
				}
				return new ApiAccessKey(payload);
			} finally {
				this.payload = null;
			}
		}
		
	}
	
	/**
	 * The payload of the access token.
	 */
	public static class Payload extends ValueObject {
		
		// NOTE: Use JWT standard and public claims only to avoid name collision issues.
		   
		@JsonbProperty("jti")
		private AccessKeyId id = randomAccessKeyId();
		
		@JsonbProperty("sub")
		private UserName userName;
		
		@JsonbProperty("iat")
		@JsonbTypeAdapter(DateToLongAdapter.class)
		private Date dateCreated;
		
		@JsonbProperty("http://rtbrick.com:methods")
		private Set<String> methods = emptySet();
		
		@JsonbProperty("http://rtbrick.com:paths")
		private Set<String> paths = emptySet();
		
		@JsonbProperty("http://rtbrick.com:short")
		private boolean temporaryAccess;
		
		
		/**
		 * Returns the unique JWT ID in UUIDv4 format.
		 * @return the unique JWT ID
		 */
		public AccessKeyId getId() {
			return id;
		}
		
		/**
		 * Returns the user ID of the authenticated user.
		 * @return the user ID of the authenticated user.
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
		
		/**
		 * Returns whether this access token is a temporary access token for short-term access.
		 * @return <code>true</code> if this access token was issues for short-term access (e.g. for OAuth flows).
		 */
		public boolean isTemporary() {
			return temporaryAccess;
		}
		
		public Set<String> getPaths() {
			return unmodifiableSet(paths);
		}
		
		public boolean isPathAllowed(String path) {
			if(paths.isEmpty()) {
				return true;
			}
			for(String pattern : paths) {
				Pattern compiled = PATTERNS.computeIfAbsent(pattern, Pattern::compile);
				if(compiled.matcher(path).matches()) {
					return true;
				}
			}
			return false;
		}
		
		public Set<String> getMethods() {
			return unmodifiableSet(methods);
		}
		
		public boolean isMethodAllowed(String method) {
			return methods.isEmpty() || methods.contains(method.toLowerCase());
		}
		
	}
	
	/**
	 * Creates an <code>ApiAccessKey</code>
	 * @param payload the access key payload
	 */
	protected ApiAccessKey(Payload payload) {
		super(payload);
	}
	
	/**
	 * Returns the user ID of the authenticated user.
	 * @return the user ID of the auchenticated user.
	 */
	public UserName getUserName() {
		return getPayload().getUserName();
	}
	
	/**
	 * Returns the creation timestamp of the access token.
	 * @return the creation timestamp of the access token.
	 */
	public Date getDateCreated() {
		return getPayload().getDateCreated();
	}
	
	/**
	 * Returns whether the API access key grants access to the specified path.
	 * @param path - the path to test
	 * @return <code>true</code> if this API access key is permitted to access the specified path.
	 */
	public boolean isPathAllowed(String path) {
		return getPayload().isPathAllowed(path);
	}
	
	/**
	 * Returns whether the API access key authorizes execution of the specified HTTP request method.
	 * @param method - the method to test
	 * @return <code>true</code> if this API access key is permitted to executed the specified HTTP request method.
	 */
	public boolean isMethodAllowed(String path) {
		return getPayload().isMethodAllowed(path);
	}

	public AccessKeyId getId() {
		return getPayload().getId();
	}

	public boolean isTemporary() {
		return getPayload().isTemporary();
	}
	
	public Set<String> getMethods() {
		return getPayload().getMethods();
	}
	
	public Set<String> getPaths() {
		return getPayload().getPaths();
	}
	
	
	
}
