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
										 .withScopes(accessKey.getScopes())
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
