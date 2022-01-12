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
package io.leitstand.security.sso.sys.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.commons.model.StringUtil.trim;

import java.net.URI;

import io.leitstand.commons.model.ValueObject;

/**
 * The <code>LoginConfiguration</code> provides the login view URL and
 * the OpenID/Connect client ID if OpenId/Connect is enabled.
 */
public class LoginConfiguration extends ValueObject {
	
	
	/**
	 * Creates a new <code>LoginConfiguration</code> builder.
	 * @return the <code>LoginConfiguration</code> builder.
	 */
	public static Builder newLoginConfiguration() {
		return new Builder();
	}
	
	/**
	 * A <code>LoginConfiguration</code> builder.
	 */
	public static class Builder {
		
		private LoginConfiguration config = new LoginConfiguration();
		
		/**
		 * Sets the Leitstand OpenID/Connect client ID.
		 * @param clientId the client ID.
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withOidcClientId(String clientId) {
			assertNotInvalidated(getClass(),config);
			clientId = trim(clientId);
			config.oidcClientId = clientId;
			config.oidcEnabled = isNonEmptyString(clientId);
			return this;
		}
		
		/**
		 * Sets the login view URL
		 * @param loginView the login view URL.
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withLoginView(String loginView) {
			return withLoginView(URI.create(loginView));
		}

		/**
		 * Sets the login view URL
		 * @param loginView the login view URL.
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withLoginView(URI loginView) {
			assertNotInvalidated(getClass(), config);
			config.loginView = loginView;
			return this;
		}
		
		/**
		 * Creates the immutable <code>LoginConfiguration</code> and invalidates this builder.
		 * Subsequent calls of the <code>build()</code> method raises an exception.
		 * @return the immutable <code>LoginConfiguration</code>.
		 */
		public LoginConfiguration build() {
			try {
				assertNotInvalidated(getClass(), config);
				return config;
			} finally {
				this.config = null;
			}
		}
	}
	
	private boolean oidcEnabled;
	private String oidcClientId;
	private URI loginView;
	
	/**
	 * Returns whether OpenID/Connect is enabled.
	 * @return <code>true</code> if OpenID/Connect is enabled, <code>false</code> otherwise.
	 */
	public boolean isOidcEnabled() {
		return oidcEnabled;
	}
	
	/**
	 * Returns the Leitstand OpenID/Connect client identifier.
	 * @return the Leitstand OpenID/Connect client identifier.
	 */
	public String getOidcClientId() {
		return oidcClientId;
	}
	
	/**
	 * Return the login view URL.
	 * @return the login view URL.
	 */
	public URI getLoginView() {
		return loginView;
	}
	
}
