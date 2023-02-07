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
package io.leitstand.security.sso.standalone;

import static java.util.ResourceBundle.getBundle;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

/**
 * Enumeration of OAuth reason codes.
 */
public enum ReasonCode implements Reason{
	OAH0001E_UNSUPPORTED_RESPONSE_TYPE,
	OAH0002E_CLIENT_ID_MISMATCH,
	SOL0001E_CANNOT_CREATE_VERIFIER,
	SOL0002E_CANNOT_SIGN_ACCESS_TOKEN,
	SOL0003E_INVALID_ACCESS_TOKEN;
	
	private static final ResourceBundle MESSAGES = getBundle("StandaloneMessages");

	
	/**
	 * {@inheritDoc}
	 */
	public String getMessage(Object... args){
		try{
			String pattern = MESSAGES.getString(name());
			return MessageFormat.format(pattern, args);
		} catch(Exception e){
			return name() + Arrays.asList(args);
		}
	}
}
