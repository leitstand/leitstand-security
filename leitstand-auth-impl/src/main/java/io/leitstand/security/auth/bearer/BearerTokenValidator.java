package io.leitstand.security.auth.bearer;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static io.leitstand.security.accesskeys.model.AccessKeyConfig.API_KEY_ID;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.http.Authorization.authorization;
import static java.util.logging.Logger.getLogger;
import static java.util.stream.Collectors.toList;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import java.util.LinkedList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.jwk.JWK;

import io.leitstand.security.accesskeys.model.AccessKeyConfig;
import io.leitstand.security.accesskeys.service.AccessKeyValidatorService;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.Authorization;
import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.jwt.DefaultJwksDecoder;
import io.leitstand.security.auth.jwt.Jwt;
import io.leitstand.security.auth.jwt.JwtDecoder;
import io.leitstand.security.auth.jwt.JwtException;
import io.leitstand.security.sso.oidc.config.OidcConfig;
import io.leitstand.security.sso.standalone.config.StandaloneLoginConfig;

/**
 * The <code>BearerTokenValidator</code> validates a bearer token against the the API access and the OpenId/Connect or standalone login key. 
 */
@ApplicationScoped
public class BearerTokenValidator implements AccessTokenManager {
	
	private static final Logger LOG = getLogger(BearerTokenValidator.class.getName());

    private OidcConfig oidcConfig;
    
    private StandaloneLoginConfig standaloneConfig;
    
    private AccessKeyConfig accessKeyConfig;
    
    private UserContextProvider userContext;
    
    private AccessKeyValidatorService accesskeys;
    
    private JwtDecoder decoder;
    
    protected BearerTokenValidator() {
    	// CDI
    }
    
    @Inject
    protected BearerTokenValidator(AccessKeyValidatorService accesskeys,
    							   UserContextProvider userContext,
    							   AccessKeyConfig accessKeyConfig,
    							   StandaloneLoginConfig standaloneConfig,
    							   OidcConfig oidcConfig) {
    	this.accesskeys = accesskeys;
    	this.userContext = userContext;
    	this.accessKeyConfig = accessKeyConfig;
    	this.standaloneConfig = standaloneConfig;
    	this.oidcConfig = oidcConfig;
    }
    
    @PostConstruct
    protected void createJwtDecoder() {
    	
    	// Build set of trusted keys.
    	List<JWK> trustedKeys = new LinkedList<>();
    	if (oidcConfig != null) {
    		trustedKeys.addAll(oidcConfig.getKeySet().getKeys());
    	}
    	if (standaloneConfig != null) {
    		trustedKeys.addAll(standaloneConfig.getKeySet().getKeys());
    	}
    	if (accessKeyConfig != null) {
    		trustedKeys.addAll(accessKeyConfig.getKeySet().getKeys());
    	}
    	
    	SortedSet<String> keyIds = new TreeSet<>(trustedKeys.stream()
    											 .map(JWK::getKeyID)
    											 .collect(toList()));
    	
    	LOG.info("Bearer tokens must signed with RS256 and use one of the following keys: "+keyIds);
    	
    	
    	decoder = new DefaultJwksDecoder(RS256, trustedKeys);
    	
    }
    
    /**
     * Validates a HTTP bearer token against all trusted keys
     * @param request the HTTP request
     * @param response the HTTP response
     * @return <code>NOT_VALIDATED_RESULT</code> if no bearer token exists, 
     * <code>INVALID_RESULT</code> if the bearer token is invalid, expired or revoked and 
     * <code>VALID</code> result if the bearer token is valid.
     */
    @Override
    public CredentialValidationResult validateAccessToken(HttpServletRequest request, HttpServletResponse response) {
		Authorization auth = authorization(request);
		if(auth != null && auth.isBearerToken()) {
			try {
				Jwt jwt = decoder.decodeToken(auth.getCredentials());
				// Reject all expired access tokens.
				if (jwt.isExpired()) {
					return INVALID_RESULT;
				}
				
				// Reject revoked access keys
				if (API_KEY_ID.equals(jwt.getKeyID()) &&  accesskeys.isRevoked(jwt)) {
					return INVALID_RESULT;
				}
				
				Claims claims = jwt.getClaims();
				String sub = claims.getSubject();
				userContext.setUserName(userName(sub));
				userContext.setScopes(claims.getScopes());
				userContext.seal();
				
				return new CredentialValidationResult(sub);
			
			} catch (JwtException e) {
				return INVALID_RESULT;
			}
		}
		return NOT_VALIDATED_RESULT;
    }

}
