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
package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static io.leitstand.commons.model.ObjectUtil.isDifferent;
import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.trim;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0100E_INVALID_ACCESSKEY;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0101E_MALFORMED_ACCESSKEY;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskeys.AccessKeyId.accessKeyId;
import static io.leitstand.security.auth.accesskeys.ApiAccessKey.newApiAccessKey;
import static io.leitstand.security.auth.jwt.Claims.newClaims;
import static java.lang.Boolean.parseBoolean;
import static java.lang.Long.parseLong;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toSet;

import java.util.Date;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskeys.AccessKeyId;
import io.leitstand.security.auth.accesskeys.ApiAccessKey;
import io.leitstand.security.auth.accesskeys.ApiAccessKeyDecoder;
import io.leitstand.security.auth.accesskeys.ApiAccessKeyEncoder;
import io.leitstand.security.auth.jwt.Claims;

/**
 * The <code>DefaultApiAccessKeyService</code> provides means to create (encode) and verify (decode) temporary API access keys.
 * Temporary API access keys are used to authenticate communication between different Leitstand services.
 */
@ApplicationScoped
public class DefaultApiAccessKeyService implements ApiAccessKeyDecoder, ApiAccessKeyEncoder {

	@Inject
	private AccessKeyConfig config;
	
	
	protected DefaultApiAccessKeyService() {
		// CDI
	}
	
	/**
	 * Creates a new <code>DefaulApiAcessKeyEncodingService</code>.
	 * @param config the API access key configuration
	 */
	public DefaultApiAccessKeyService(AccessKeyConfig config) {
		this.config = config;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String encode(ApiAccessKey key) {
	    
	    Claims.Builder claims = newClaims()
	                            .jwtId(AccessKeyId.toString(key.getId()))
	                            .issuedAt(key.getDateCreated())
	                            .expiresAt(key.getDateExpiry())
	                            .subject(UserName.toString(key.getUserName()))
	                            .scopes(key.getScopes());
	            
	    if (key.isTemporary()) {
	        claims.claim("temporary","true");
	    }
	    
	    return config.signApiAccessKey(claims);
	}


	/**
	 * {@inheritDoc}
	 */
	@Override
	public ApiAccessKey decode(String encodedToken) {
	    if (encodedToken.indexOf('.') < 0) {
	        return legacyDecode(encodedToken);
	    }
	     
	    Claims claims = config.decodeAccessKey(encodedToken);
	    Set<String> scopes = claims.getScopes();
	    return newApiAccessKey()
	           .withId(accessKeyId(claims.getJwtId()))
	           .withDateCreated(claims.getIssuedAt())
	           .withDateExpiry(claims.getExpiresAt())
	           .withUserName(userName(claims.getSubject()))
	           .withTemporaryAccess(parseBoolean(claims.getClaim("temporary")))
	           .withScopes(scopes)
	           .build();

	}


	@Deprecated
	private ApiAccessKey legacyDecode(String encodedToken) {
	    String token = decodeToken(encodedToken);
        int    lastColon  = token.lastIndexOf(':');
        
        if (lastColon < 0 || token.endsWith(":")) {
            throw new AccessDeniedException(AKY0101E_MALFORMED_ACCESSKEY);
        }
        
        String tokenData  = token.substring(0, lastColon);
        String signature  = token.substring(lastColon+1);
        if(isDifferent(signature, config.apiKeyHmac(tokenData))) {
            throw new AccessDeniedException(AKY0100E_INVALID_ACCESSKEY);
        }
        
        String[] segments = tokenData.split(":");
        AccessKeyId id = accessKeyId(segments[0]);
        UserName userName = userName(segments[1]); 
        Set<String> scopes = stream(segments[2].split(","))
                             .filter(s -> s.length() > 0)
                             .collect(toSet());
        
        boolean temporary = parseBoolean(segments[3]);
        Date dateCreated = new Date(parseLong(segments[4]));
        
        return newApiAccessKey()
               .withId(id)
               .withUserName(userName)
               .withScopes(scopes)
               .withTemporaryAccess(temporary)
               .withDateCreated(dateCreated)
               .build();
	}
	
    private String decodeToken(String encodedToken) {
        try {
            return trim(fromUtf8Bytes(decodeBase64String(encodedToken)));
        } catch (IllegalArgumentException e) {
            throw new UnprocessableEntityException(AKY0101E_MALFORMED_ACCESSKEY);
        }
    }

}
