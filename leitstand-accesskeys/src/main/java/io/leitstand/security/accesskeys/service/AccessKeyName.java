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
package io.leitstand.security.accesskeys.service;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.accesskeys.jsonb.AccessKeyNameAdapter;

@JsonbTypeAdapter(AccessKeyNameAdapter.class)
public class AccessKeyName extends Scalar<String>{

	private static final long serialVersionUID = 1L;

	public static AccessKeyName accessKeyName(String name) {
	    return valueOf(name);
	}
	
	public static AccessKeyName accessKeyName(Scalar<String> name) {
	    return valueOf(name);
	}
	
	public static AccessKeyName valueOf(String name) {
		return fromString(name,AccessKeyName::new);
	}
	
	public static AccessKeyName valueOf(Scalar<String> name) {
		return valueOf(name.toString());
	}
	
	
	@NotNull(message="{key_name.required}")
	@Pattern(message="{key_name.invalid}", regexp="\\p{Print}{1,64}")
	private String value;
	
	public AccessKeyName(String value) {
		this.value = value;
	}
	
	@Override
	public  String getValue() {
		return value;
	}


	
}
