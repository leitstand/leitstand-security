package io.leitstand.security.auth.http;

import java.net.URI;

import io.leitstand.commons.model.ValueObject;
import static io.leitstand.commons.model.BuilderUtil.*;
public class LoginConfiguration extends ValueObject {
	
	public static LoginConfiguration newDefaultLoginConfiguration() {
		return newLoginConfiguration()
			   .withLoginView(URI.create("/ui/login/login.html"))
			   .withOidcEnabled(false)
			   .build();
	}

	public static Builder newLoginConfiguration() {
		return new Builder();
	}
	
	public static class Builder {
		
		private LoginConfiguration config = new LoginConfiguration();
		
		public Builder withOidcEnabled(boolean oidcEnabled) {
			assertNotInvalidated(getClass(),config);
			config.oidcEnabled = oidcEnabled;
			return this;
		}
	
		public Builder withOidcClientId(String clientId) {
			assertNotInvalidated(getClass(),config);
			config.oidcClientId = clientId;
			return this;
		}
		
		public Builder withLoginView(String authorizationEndpoint) {
			return withLoginView(URI.create(authorizationEndpoint));
		}
		
		public Builder withLoginView(URI loginView) {
			assertNotInvalidated(getClass(), config);
			config.loginView = loginView;
			return this;
		}
		
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
	
	public boolean isOidcEnabled() {
		return oidcEnabled;
	}
	
	public String getOidcClientId() {
		return oidcClientId;
	}
	
	public URI getLoginView() {
		return loginView;
	}
	
}
