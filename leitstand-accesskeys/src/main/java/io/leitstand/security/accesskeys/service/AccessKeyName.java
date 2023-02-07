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

/**
 * The unique access key name.
 */
@JsonbTypeAdapter(AccessKeyNameAdapter.class)
public class AccessKeyName extends Scalar<String>{

	private static final long serialVersionUID = 1L;

	/**
	 * Creates an access key name from the given string.
	 * Returns <code>null</code> if the given string is <code>null</code> or empty. 
	 * <p>
	 * This method is an alias of the {@link #valueOf(String)} method to avoid static import conflicts.
	 * @param name the access key name
	 * @return the typed access key name
	 */
	public static AccessKeyName accessKeyName(String name) {
	    return valueOf(name);
	}

	/**
	 * Creates an access key name from the given scalar.
 	 * Returns <code>null</code> if the given scalar is <code>null</code>.
 	 * This method is an alias of the {@link #valueOf(Scalar)} method to avoid static import conflicts.
	 * @param name the access key name.
	 * @return the typed access key name
	 */
	public static AccessKeyName accessKeyName(Scalar<String> name) {
	    return valueOf(name);
	}
	
	/**
	 * Creates an access key name from the given string.
	 * Returns <code>null</code> if the given name is <code>null</code> or empty.
	 * @param name the access key name.
	 * @return the typed access key name.
	 */
	public static AccessKeyName valueOf(String name) {
		return fromString(name,AccessKeyName::new);
	}
	
	/**
	 * Creates an access key name from the given scalar.
 	 * Returns <code>null</code> if the given scalar is <code>null</code>.
	 * @param name the access key name.
	 * @return the typed access key name
	 */
	public static AccessKeyName valueOf(Scalar<String> name) {
		return valueOf(name.toString());
	}
	
	
	@NotNull(message="{key_name.required}")
	@Pattern(message="{key_name.invalid}", regexp="\\p{Print}{1,64}")
	private String value;
	
	/**
	 * Creates a new <code>AccessKeyName</code>.
	 * @param value the access key name
	 */
	public AccessKeyName(String value) {
		this.value = value;
	}
	
	/**
	 * Returns the access key name.
	 * @return the access key name.
	 */
	@Override
	public  String getValue() {
		return value;
	}


	
}
