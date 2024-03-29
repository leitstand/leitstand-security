package io.leitstand.security.sys.model;

import static io.leitstand.security.oauth2.Oauth2AccessToken.newOauth2AccessToken;
import static java.lang.System.currentTimeMillis;

import java.util.Date;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;

import io.leitstand.security.oauth2.Oauth2AccessToken;
import io.leitstand.security.sso.oidc.config.OidcConfig;
import io.leitstand.security.sso.oidc.oauth2.RefreshTokenStore;
import io.leitstand.security.sso.oidc.service.OidcService;

@Dependent
public class OidcAccessTokenRefresh {

    private OidcService client;
    
    private RefreshTokenStore refreshTokens;
    
    private OidcConfig oidcConfig;
    
    protected OidcAccessTokenRefresh() {
    	// CDI
    }
    
    @Inject
    protected OidcAccessTokenRefresh(OidcService client, OidcConfig oidcConfig, RefreshTokenStore refreshTokens) {
    	this.client = client;
    	this.oidcConfig = oidcConfig;
    	this.refreshTokens = refreshTokens;
    }
    
    public Oauth2AccessToken refreshAccessToken(String accessToken) {

        // Refresh access token and store new refresh token.
        String sub = subject(accessToken);
        String refreshToken = refreshTokens.getRefreshToken(sub);
        Oauth2AccessToken oauth2 = client.refreshAccessToken(refreshToken);
        refreshTokens.storeRefreshToken(sub, 
        								oauth2.getRefreshToken(),
        								new Date(currentTimeMillis()+1000*oauth2.getRefreshExpiresIn()));

        // Do not expose refresh token to client!
     
        return newOauth2AccessToken()
               .withAccessToken(oauth2.getAccessToken())
               .withExpiresIn(oauth2.getExpiresIn())
               .build();
    }

    private String subject(String accessToken) {
        return oidcConfig.decodeAccessToken(accessToken).getSubject();
    }

    public boolean isOidcEnabled() {
        return oidcConfig != null;
    }
    
}
