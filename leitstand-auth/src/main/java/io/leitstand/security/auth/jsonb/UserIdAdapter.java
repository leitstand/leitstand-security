/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jsonb;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.security.auth.UserId;

public class UserIdAdapter implements JsonbAdapter<UserId,String> {

	@Override
	public UserId adaptFromJson(String v) throws Exception {
		return UserId.valueOf(v);
	}

	@Override
	public String adaptToJson(UserId v) throws Exception {
		return UserId.toString(v);
	}

}
