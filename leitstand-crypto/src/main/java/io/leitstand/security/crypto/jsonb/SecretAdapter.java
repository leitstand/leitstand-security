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
