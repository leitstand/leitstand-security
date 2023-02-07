package io.leitstand.security.sso.standalone.oauth2;

import io.leitstand.commons.model.ValueObject;

class CodePayload extends ValueObject {

	private String userName;
	private String clientId;
	
	CodePayload(String clientId, String userName){
		this.clientId = clientId;
		this.userName = userName;
	}
	
	String getUserName() {
		return userName;
	}
	
	String getClientId() {
		return clientId;
	}
}
