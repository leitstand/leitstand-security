/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.flow;

import static io.leitstand.security.accesskeys.service.AccessKeyData.newAccessKey;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;

import java.util.Date;

import io.leitstand.security.accesskeys.service.AccessKeyData;
import io.leitstand.security.accesskeys.service.AccessKeyService;
import io.leitstand.security.auth.accesskey.AccessKeyId;

public class RenewAccessKeyFlow {

	private AccessKeyService service;
	private String newAccessToken;
	private AccessKeyId newAccessTokenId;
	
	public RenewAccessKeyFlow(AccessKeyService service) {
		this.service = service;
	}
	
	
	public void renew(AccessKeyId accessKeyId) {
		service.removeAccessKey(accessKeyId);
		AccessKeyData accessKey = service.getAccessKey(accessKeyId);
		newAccessTokenId = randomAccessKeyId();
		AccessKeyData renewedAccessKey = newAccessKey()
										 .withAccessKeyId(newAccessTokenId)
										 .withAccessKeyName(accessKey.getAccessKeyName())
										 .withDateCreated(new Date())
										 .withDescription(accessKey.getDescription())
										 .withMethods(accessKey.getMethods())
										 .withPaths(accessKey.getPaths())
										 .build();
		newAccessToken = service.createAccessKey(renewedAccessKey);
	}
	
	public String getNewAccessToken() {
		return newAccessToken;
	}
	
	public AccessKeyId getNewAccessTokenId() {
		return newAccessTokenId;
	}
	
}
