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
package io.leitstand.security.accesskeys.jsonb;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.accesskeys.service.AccessKeyName;


/**
 * <code>AccessKeyName</code> JSON-B adapter.
 */
public class AccessKeyNameAdapter implements JsonbAdapter<AccessKeyName,String> {

	/**
	 * Converts an <code>AccessKeyName</code> to a string.
	 * @param name the access key name
	 * @return the string representation of the given access key name or <code>null</code> if the given access key name is <code>null</code>.
	 */
	@Override
	public AccessKeyName adaptFromJson(String name) throws Exception {
		return AccessKeyName.valueOf(name);
	}

	/**
	 * Creates an <code>AccessKeyName</code> from the given string.
	 * @param name the access key name
	 * @return the <code>AccessKeyName</code> or <code>null</code> if the given key name is <code>null</code> or empty.
	 */
	@Override
	public String adaptToJson(AccessKeyName name) throws Exception {
		return Scalar.toString(name);
	}

}
