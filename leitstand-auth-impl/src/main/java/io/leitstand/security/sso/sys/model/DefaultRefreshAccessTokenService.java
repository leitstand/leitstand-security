package io.leitstand.security.sso.sys.model;

import static io.leitstand.commons.model.ObjectUtil.isDifferent;
import static io.leitstand.security.sso.sys.service.ReasonCode.SYS0001E_INVALID_SYSTEM_CREDENTIALS;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.etc.Environment;
import io.leitstand.security.oauth2.Oauth2AccessToken;
import io.leitstand.security.sso.sys.service.RefreshAccessTokenService;

@ApplicationScoped
public class DefaultRefreshAccessTokenService implements RefreshAccessTokenService {

    @Inject
    private OidcAccessTokenRefresh oidcRefresh;
    
    @Inject
    private StandaloneAccessTokenRefresh standaloneRefresh;

    
    @Override
    public Oauth2AccessToken refreshAccessToken(String systemId, String systemSecret, String accessToken) {

        // Check that the client is allowed to refresh an access token.
        checkAccess(systemId, systemSecret);
        
        if (oidcRefresh.isOidcEnabled()) {
            return oidcRefresh.refreshAccessToken(accessToken);
        }

        return standaloneRefresh.refreshAccessToken(accessToken);
        
    }
    
    private void checkAccess(String systemId, String systemSecret) {
        if (isDifferent(Environment.getSystemProperty("SYSTEM_CLIENT_ID","leitstand"),systemId) 
            || isDifferent(Environment.getSystemProperty("SYSTEM_CLIENT_SECRET","changeit"),systemSecret)) {
            throw new AccessDeniedException(SYS0001E_INVALID_SYSTEM_CREDENTIALS);
        }
    }
    
}
