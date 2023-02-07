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

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0005E_DUPLICATE_KEY_NAME;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0006E_DATABASE_ERROR;

import io.leitstand.commons.messages.Messages;
import io.leitstand.security.accesskeys.service.AccessKeyService;
import io.leitstand.security.accesskeys.service.AccessKeySettings;

/**
 * The <code>CreateAccessKeyFlow</code> adds a new access key or reports an error, if the new access key cannot be created.
 */
public class CreateAccessKeyFlow {

	private AccessKeyService service;
	private Messages messages;
	
	/**
	 * Creates a new <code>CreateAccessKeyFlow</code>
	 * @param service the access key service
	 * @param messages the container for reporting status and error messages
	 */
	public CreateAccessKeyFlow(AccessKeyService service,
							   Messages messages) {
		this.service = service;
		this.messages = messages;
	}
	
	/**
	 * Creates a new access key from the given access key settings.
	 * @param accessKey the access key settings
	 * @return the encoded access key or <code>null</code> if the access key cannot be created.
	 */
	public String tryCreateAccessKey(AccessKeySettings accessKey) {
		try {
			return service.createAccessKey(accessKey);
		} catch(Exception e) {
			if(!service.findAccessKeys(accessKey.getAccessKeyName().getValue()).isEmpty()) {
				messages.add(createMessage(AKY0005E_DUPLICATE_KEY_NAME, 
										   "key_name",
										   accessKey.getAccessKeyName()));
				return null;
			} 
			messages.add(createMessage(AKY0006E_DATABASE_ERROR,
									   e.getMessage()));
			return null;
		}
	}
	
	
}
