/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.auth;

import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static io.leitstand.commons.model.ByteArrayUtil.encodeBase64String;
import static io.leitstand.commons.model.ObjectUtil.isDifferent;
import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmacSha256;
import static java.lang.Boolean.parseBoolean;
import static java.lang.Long.parseLong;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toSet;

import java.util.Date;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.AccessKeyId;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyDecoder;
import io.leitstand.security.auth.accesskey.ApiAccessKeyEncoder;
import io.leitstand.security.auth.jwt.JsonWebTokenConfig;
import io.leitstand.security.auth.jwt.JsonWebTokenSignatureException;

@ApplicationScoped
public class AccessKeyEncodingService implements ApiAccessKeyDecoder, ApiAccessKeyEncoder {

	@Inject
	private JsonWebTokenConfig config;
	
	public AccessKeyEncodingService() {
		// CDI
	}
	
	public AccessKeyEncodingService(JsonWebTokenConfig config) {
		this.config = config;
	}
	
	/* (non-Javadoc)
	 * @see net.rtbrick.rbms.security.km.model.CompactAccessKeyEncodingService#encodeCompact(net.rtbrick.rbms.security.auth.http.ApiAccessKey)
	 */
	@Override
	public String encode(ApiAccessKey key) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(key.getId())
			  .append(":")
			  .append(key.getUserName())
			  .append(":")
			  .append(key.getMethods().stream().collect(joining(",")))
			  .append(":")
			  .append(key.getPaths().stream().collect(joining(",")))
			  .append(":")
			  .append(key.isTemporary())
			  .append(":")
			  .append(key.getDateCreated().getTime());
		String sign64 = sign64(buffer.toString());  
		buffer.append(":")
			  .append(sign64);
		return encodeBase64String(toUtf8Bytes(buffer.toString()));
	}

	private String sign64(String tokenData) {
		return encodeBase64String(hmacSha256(config.getSecret()).sign(tokenData));
	}
	
	/* (non-Javadoc)
	 * @see net.rtbrick.rbms.security.km.model.CompactAccessKeyEncodingService#decodeCompact(java.lang.String)
	 */
	@Override
	public ApiAccessKey decode(String encodedToken) {
		String token = fromUtf8Bytes(decodeBase64String(encodedToken));
		int    lastColon  = token.lastIndexOf(':');
		String tokenData  = token.substring(0, lastColon);
		String signature  = token.substring(lastColon+1);
		if(isDifferent(signature, sign64(tokenData))) {
			throw new JsonWebTokenSignatureException("Signature mismatch!");
		}
		String[] segments = tokenData.split(":");
 		AccessKeyId id = AccessKeyId.accessKeyId(segments[0]);
		UserName userName = userName(segments[1]); 
		Set<String> methods = stream(segments[2].split(","))
							  .filter(s -> s.length() > 0)
			    			  .collect(toSet());
		Set<String> paths = stream(segments[3].split(","))
							.filter(s -> s.length() > 0)
			    			.collect(toSet());
		boolean temporary = parseBoolean(segments[4]);
		Date dateCreated = new Date(parseLong(segments[5]));
		
		return newApiAccessKey()
			   .withId(id)
			   .withUserName(userName)
			   .withMethods(methods)
			   .withPaths(paths)
			   .withTemporaryAccess(temporary)
			   .withDateCreated(dateCreated)
			   .build();
		
	}
	
}
