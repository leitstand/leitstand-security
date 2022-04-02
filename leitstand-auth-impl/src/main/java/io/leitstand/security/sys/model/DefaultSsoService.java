package io.leitstand.security.sys.model;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.security.sys.service.LoginConfiguration.newLoginConfiguration;
import static io.leitstand.security.sys.service.SsoSettings.newSsoSettings;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import io.leitstand.security.accesskeys.model.AccessKeyConfig;
import io.leitstand.security.sso.oidc.config.OidcConfig;
import io.leitstand.security.sso.standalone.config.StandaloneLoginConfig;
import io.leitstand.security.sys.service.LoginConfiguration;
import io.leitstand.security.sys.service.LoginConfigurationService;
import io.leitstand.security.sys.service.SsoSettings;
import io.leitstand.security.sys.service.SsoSettingsService;

@ApplicationScoped
public class DefaultSsoService implements SsoSettingsService, LoginConfigurationService{

    @Inject
    private AccessKeyConfig accessKeyConfig;
    
    @Inject
    private StandaloneLoginConfig standaloneConfig;
    
    @Inject
    private OidcConfig oidcConfig;
    
    private JWKSet trustedKeys;
    
    @PostConstruct
    public void createTrustedKeySet() {
    	
    	List<JWK> keys = new LinkedList<>();
    	    	
    	if (accessKeyConfig != null) {
    		keys.addAll(accessKeyConfig.getKeySet().getKeys());
    	}
    	
    	if (standaloneConfig != null) {
    		keys.addAll(standaloneConfig.getKeySet().getKeys());
    	}
    	
    	if (oidcConfig != null) {
    		keys.addAll(oidcConfig.getKeySet().getKeys());
    	}
    	
    	trustedKeys = new JWKSet(keys);
    	
    	
    }
    
    @Override
    public SsoSettings getSsoSettings() {
        URI tokenEndpoint = service("/system/auth/token");
        URI jwksEndpoint = service("/system/auth/config/jwks");
        
        return newSsoSettings()
               .withJwksUri(jwksEndpoint)
               .withTokenEndpoint(tokenEndpoint)
               .build();
    }

    private URI service(String path) {
        String host = getSystemProperty("INVENTORY_ENDPOINT","http://rbms-app:8080");
        if (host.endsWith("/")) {
            host = host.substring(0,host.length()-1);
        }
        return URI.create(host+path);
    }
    
    
    @Override
    public JWKSet getJWKSet() {
        return trustedKeys;
    } 
   
	@Override
	public LoginConfiguration getLoginConfiguration() {
		if (oidcConfig != null ) {
			return newLoginConfiguration()
				   .withOidcClientId(oidcConfig.getClientId().toString())
				   .withLoginView(oidcConfig.getAuthorizationEndpoint())
				   .build();
		}
		
		return newLoginConfiguration().withLoginView("/ui/login/login.html").build();
		

	}
    
}
