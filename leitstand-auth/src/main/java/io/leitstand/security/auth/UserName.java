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
package io.leitstand.security.auth;

import java.security.Principal;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.jsonb.UserNameAdapter;

/**
 * The identifier of an authenticated user.
 */
@JsonbTypeAdapter(UserNameAdapter.class)
public class UserName extends Scalar<String> {

	private static final long serialVersionUID = 1L;

	/**
	 * Alias for the {@link #valueOf(Principal)} method.
	 * <p>
	 * Creates a <code>UserName</code> from the given principal's name.
	 * @param principal the principal name
	 * @return the created <code>UserName</code> or <code>null</code> if the
	 * specified <code>Principal</code> is <code>null</code> or the principal's name is <code>null</code> or empty.
	 */
	public static UserName userName(Principal principal) {
		return valueOf(principal);
	}
	
	/**
	 * Alias for the {@link #valueOf(String)} method.
	 * <p>
	 * Creates a <code>UserName</code> from the specified string.
	 * @param userName the user name.
	 * @return the created <code>UserName</code> instance or 
	 * <code>null</code> if the specified string is <code>null</code> or empty.
	 */
	public static UserName userName(String name) {
		return valueOf(name);
	}
	
	/**
	 * Creates a <code>UserName</code> from the specified string.
	 * @param UserName the user id.
	 * @return the created <code>UserName</code> instance or 
	 * <code>null</code> if the specified string is <code>null</code> or empty.
	 */
	public static UserName valueOf(String name) {
		return fromString(name,UserName::new);
	}
	

	public static UserName valueOf(Principal principal) {
		return principal != null ? valueOf(principal.getName()) : null; 
	}
	
	@NotNull(message="{user_name.required}")
	@Pattern(regexp="\\p{Graph}{2,64}", 
			 message="{user_name.invalid}")
	private String value;
	
	/**
	 * Creates a <code>UserName</code>.
	 * @param value the user ID
	 */
	public UserName(String value){
		this.value = value;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getValue() {
		return value;
	}

	/**
	 * Returns the user name length in characters.
	 * @return the suer name length in characters.
	 */
	public int length() {
		return value.length();
	}



}
