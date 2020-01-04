/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.flow;

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0005E_DUPLICATE_KEY_NAME;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0006E_DATABASE_ERROR;

import io.leitstand.commons.messages.Messages;
import io.leitstand.security.accesskeys.service.AccessKeyData;
import io.leitstand.security.accesskeys.service.AccessKeyService;

public class CreateAccessKeyFlow {

	private AccessKeyService service;
	private Messages messages;
	
	public CreateAccessKeyFlow(AccessKeyService service,
							   Messages messages) {
		this.service = service;
		this.messages = messages;
	}
	
	
	public String tryCreateAccessKey(AccessKeyData accessKey) {
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
