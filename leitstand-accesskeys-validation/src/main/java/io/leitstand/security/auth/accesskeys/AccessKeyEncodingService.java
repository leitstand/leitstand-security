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
package io.leitstand.security.auth.accesskeys;

import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static io.leitstand.commons.model.ByteArrayUtil.encodeBase64String;
import static io.leitstand.commons.model.ObjectUtil.isDifferent;
import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.trim;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static io.leitstand.security.auth.accesskeys.ReasonCode.AKY0100E_INVALID_ACCESSKEY;
import static io.leitstand.security.auth.accesskeys.ReasonCode.AKY0101E_MALFORMED_ACCESSKEY;
import static java.lang.Boolean.parseBoolean;
import static java.lang.Long.parseLong;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toSet;

import java.util.Date;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.AccessKeyId;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyDecoder;
import io.leitstand.security.auth.accesskey.ApiAccessKeyEncoder;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;

@ApplicationScoped
public class AccessKeyEncodingService implements ApiAccessKeyDecoder, ApiAccessKeyEncoder {

	@Inject
	private StandaloneLoginConfig config;
	
	public AccessKeyEncodingService() {
		// CDI
	}
	
	public AccessKeyEncodingService(StandaloneLoginConfig config) {
		this.config = config;
	}
	
	@Override
	public String encode(ApiAccessKey key) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(key.getId())
			  .append(":")
			  .append(key.getUserName())
			  .append(":")
			  .append(key.getScopes().stream().collect(joining(",")))
			  .append(":")
			  .append(key.isTemporary())
			  .append(":")
			  .append(key.getDateCreated().getTime());
		String hmac64 = config.apiKeyHmac(buffer.toString());  
		buffer.append(":")
			  .append(hmac64);
		return encodeBase64String(toUtf8Bytes(buffer.toString()));
	}

	
	@Override
	public ApiAccessKey decode(String encodedToken) {
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
 		AccessKeyId id = AccessKeyId.accessKeyId(segments[0]);
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

	@Override
	public boolean isApiAccessKey(String key) {
	    // JWS tokens contains a '.' as delimiter of token segments.
	    // Thus a key without '.' is an API access key issued by Leitstand.
		return !key.contains(".");
	}
	
}
