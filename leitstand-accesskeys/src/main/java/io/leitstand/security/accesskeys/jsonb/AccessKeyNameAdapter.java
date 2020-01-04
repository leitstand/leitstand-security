/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.jsonb;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.security.accesskeys.service.AccessKeyName;


public class AccessKeyNameAdapter implements JsonbAdapter<AccessKeyName,String> {

	@Override
	public AccessKeyName adaptFromJson(String v) throws Exception {
		return AccessKeyName.valueOf(v);
	}

	@Override
	public String adaptToJson(AccessKeyName v) throws Exception {
		return AccessKeyName.toString(v);
	}

}
