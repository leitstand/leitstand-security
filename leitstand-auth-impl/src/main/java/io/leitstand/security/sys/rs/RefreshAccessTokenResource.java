package io.leitstand.security.sys.rs;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.inject.Inject;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.oauth2.Oauth2AccessToken;
import io.leitstand.security.sys.service.RefreshAccessTokenService;

/**
 * REST resource to refresh an expired access token.
 */
@Resource
@Path("/auth/token")
@Produces(APPLICATION_JSON)
public class RefreshAccessTokenResource {

    
    private RefreshAccessTokenService service;
    
    protected RefreshAccessTokenResource() {
    	// CDI
    }
    
    @Inject
    protected RefreshAccessTokenResource(RefreshAccessTokenService service) {
    	this.service = service;
    }
    
    
    /**
     * POST method to refresh an expired access token.
     * @param clientId client ID to authenticate the refresh request
     * @param clientSecret client secret to authenticate the refresh request.
     * @param accessToken the access token to be refreshed.
     * @return the refreshed access token
     * @throws AccessDeniedException if the client credentials or the access token is invalid 
     * or if the access token cannot be refreshed for any other reason.
     */
    @POST
    public Oauth2AccessToken refresh(@FormParam("client_id") String clientId,
                                     @FormParam("client_secret") String clientSecret,
                                     @FormParam("access_token") String accessToken) {
        return service.refreshAccessToken(clientId, clientSecret, accessToken);
    }
    
    
}
