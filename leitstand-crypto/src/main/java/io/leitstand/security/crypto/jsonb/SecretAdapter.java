/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.crypto.jsonb;

import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.security.crypto.Secret;

/**
 * Maps a {@link Secret} to a string and creates a {@link Secret} from a string respectively.
 */
public class SecretAdapter implements JsonbAdapter<Secret,String> {

	/**
	 * Creates a <code>Secret</code> from a string.
	 * Returns <code>null</code> if the string is <code>null</code> or empty.
	 * @return the adaptFromJsonled secret
	 */
	@Override
	public Secret adaptFromJson(String v) throws Exception {
		if(isNonEmptyString(v)){
			return new Secret(toUtf8Bytes(v));
		}
		return null;
	}

	/**
	 * Marshalls a <code>Secret</code> op a string.
	 * Returns <code>null</code> if the secret is <code>null</code>.
	 * @return the adaptToJsonled secret
	 */
	@Override
	public String adaptToJson(Secret v) throws Exception {
		if(v == null){
			return null;
		}
		return v.toString();
	}

}