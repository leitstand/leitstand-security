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
package io.leitstand.security.accesskeys.flow;

import static io.leitstand.security.accesskeys.service.AccessKeySettings.newAccessKeySettings;
import static io.leitstand.security.auth.accesskeys.AccessKeyId.randomAccessKeyId;

import java.util.Date;

import io.leitstand.security.accesskeys.service.AccessKeyService;
import io.leitstand.security.accesskeys.service.AccessKeySettings;
import io.leitstand.security.auth.accesskeys.AccessKeyId;

/**
 * The <code>RenewAccessKeyFlow</code> allows renewing an existing access key by creating a new access key token with a UUID. 
 * This implicitly revokes the old token.
 */
public class RenewAccessKeyFlow {

	private AccessKeyService service;
	private String newAccessToken;
	private AccessKeyId newAccessTokenId;
	
	/**
	 * Creates a new <code>RenewAccessKeyFlow</code>.
	 * @param service the access key service
	 */
	public RenewAccessKeyFlow(AccessKeyService service) {
		this.service = service;
	}
	
	
	/**
	 * Renews the access key with the given ID by creating a new access key with a new UUID. 
	 * This invalidates the access token that has been issued for this access key.
	 * @param accessKeyId the access key ID.
	 */
	public void renew(AccessKeyId accessKeyId) {
		service.removeAccessKey(accessKeyId);
		AccessKeySettings accessKey = service.getAccessKey(accessKeyId);
		newAccessTokenId = randomAccessKeyId();
		AccessKeySettings renewedAccessKey = newAccessKeySettings()
										 .withAccessKeyId(newAccessTokenId)
										 .withAccessKeyName(accessKey.getAccessKeyName())
										 .withDateCreated(new Date())
										 .withDescription(accessKey.getDescription())
										 .withScopes(accessKey.getScopes())
										 .build();
		newAccessToken = service.createAccessKey(renewedAccessKey);
	}
	
	/**
	 * Returns the new access token.
	 * @return the renewed access token.
	 */
	public String getNewAccessToken() {
		return newAccessToken;
	}
	
	/**
	 * Returns the new access key ID.
	 * @return the new access key ID.
	 */
	public AccessKeyId getNewAccessTokenId() {
		return newAccessTokenId;
	}
	
}
