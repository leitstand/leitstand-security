/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.accesskey;

import java.util.UUID;

import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.jsonb.AccessKeyIdAdapter;

@JsonbTypeAdapter(AccessKeyIdAdapter.class)
public class AccessKeyId extends Scalar<String>{

	private static final long serialVersionUID = 1L;

	public static AccessKeyId accessKeyId(String id) {
		return valueOf(id);
	}
	
	public static AccessKeyId randomAccessKeyId() {
		return valueOf(UUID.randomUUID().toString());
	}
	
	public static AccessKeyId valueOf(String id) {
		return fromString(id,AccessKeyId::new);
	}

	private String value;
	
	public AccessKeyId(String value) {
		this.value = value;
	}
	
	@Override
	public  String getValue() {
		return value;
	}

	
}
