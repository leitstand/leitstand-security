package io.leitstand.security.sso.sys.service;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.security.oauth2.Oauth2AccessToken;

/**
 * The <code>RefreshAccessTokenService</code> allows refreshing an expired access token.
 * The service can decline the refresh request by throwing an {@link AccessDeniedException}.
 */
public interface RefreshAccessTokenService {

    /**
     * Refreshes an expired access token.
     * @param systemId the system ID
     * @param systemSecret the system secret
     * @param accessToken the access token to be refreshed
     * @return the refreshed access token
     * @throws AccessDeniedException when the access token cannot be refreshed or the system credentials are invalid
     */
    Oauth2AccessToken refreshAccessToken(String systemId, String systemSecret, String accessToken);
    
}
