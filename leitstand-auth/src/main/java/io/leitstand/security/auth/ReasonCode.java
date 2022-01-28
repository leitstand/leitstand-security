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

import static java.text.MessageFormat.format;
import static java.util.Arrays.asList;
import static java.util.ResourceBundle.getBundle;

import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

/**
 * Enumeration of authentication-related reason codes.
 * @author mast
 *
 */
public enum ReasonCode implements Reason {

	/** Unauthenticated users are not allowed to access this resource.*/
	AUT0001E_UNAUTHENTICATED_ACCESS_DENIED,
	/** The authenticated user is not authorized to access this resource.*/ 
	AUT0002E_SCOPE_ACCESS_DENIED;
	
	private static final ResourceBundle MESSAGES = getBundle("AuthMessages");
	
	/**
	 * {@inheritDoc}
	 */
	public String getMessage(Object... args){
		try{
			String pattern = MESSAGES.getString(name());
			return format(pattern, args);
		} catch(Exception e){
			return name() + asList(args);
		}
	}
	
}
