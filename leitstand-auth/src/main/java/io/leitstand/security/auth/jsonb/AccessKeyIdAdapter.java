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
package io.leitstand.security.auth.jsonb;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.accesskeys.AccessKeyId;


/**
 * <code>AccessKeyId</code> JSON-B adapter.
 */
public class AccessKeyIdAdapter implements JsonbAdapter<AccessKeyId,String> {

	/**
	 * Creates a <code>AccessKeyId</code> from the given string.
	 * @param id the access key ID
	 * @return the typed access key ID or <code>null</code> if the given string is <code>null</code> or empty
	 */
	@Override
	public AccessKeyId adaptFromJson(String id) throws Exception {
		return AccessKeyId.valueOf(id);
	}

	/**
	 * Converts a <code>AccessKeyId</code> to a string.
	 * @param id the access key ID
	 * @return the string representation of the given access key ID or <code>null</code> if the given access key is <code>null</code>
	 */
	@Override
	public String adaptToJson(AccessKeyId id) throws Exception {
		return Scalar.toString(id);
	}

}
