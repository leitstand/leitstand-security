package io.leitstand.security.sso.sys.model;

import javax.enterprise.context.Dependent;

import io.leitstand.security.oauth2.Oauth2AccessToken;

@Dependent
public class StandaloneAccessTokenRefresh {

    
    public Oauth2AccessToken refreshAccessToken(String accessToken) {
        throw new UnsupportedOperationException();
    }
    
}
