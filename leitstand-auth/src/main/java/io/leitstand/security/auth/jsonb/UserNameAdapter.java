/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jsonb;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.security.auth.UserName;

public class UserNameAdapter implements JsonbAdapter<UserName,String> {

	@Override
	public UserName adaptFromJson(String v) throws Exception {
		return UserName.valueOf(v);
	}

	@Override
	public String adaptToJson(UserName v) throws Exception {
		return UserName.toString(v);
	}

}
