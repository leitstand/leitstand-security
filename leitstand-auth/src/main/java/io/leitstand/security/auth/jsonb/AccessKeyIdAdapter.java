/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jsonb;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.security.auth.accesskey.AccessKeyId;


public class AccessKeyIdAdapter implements JsonbAdapter<AccessKeyId,String> {

	@Override
	public AccessKeyId adaptFromJson(String v) throws Exception {
		return AccessKeyId.valueOf(v);
	}

	@Override
	public String adaptToJson(AccessKeyId v) throws Exception {
		return AccessKeyId.toString(v);
	}

}
