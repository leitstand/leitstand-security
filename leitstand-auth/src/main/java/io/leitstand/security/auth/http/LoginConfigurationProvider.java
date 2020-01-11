package io.leitstand.security.auth.http;

import static io.leitstand.security.auth.http.LoginConfiguration.newDefaultLoginConfiguration;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;

@ApplicationScoped
public class LoginConfigurationProvider {

	@Produces
	private LoginConfiguration loginConfiguration;
	
	@PostConstruct
	void setDefaultLoginConfiguration(){
		this.loginConfiguration = newDefaultLoginConfiguration();
	}
	
	
	public void setLoginConfiguration(LoginConfiguration loginConfiguration) {
		this.loginConfiguration = loginConfiguration;
	}
	
}
