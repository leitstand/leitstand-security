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

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

/**
 * Enumeration of access-key management reason codes.
 */
public enum ReasonCode implements Reason{
	
	/**
	 * The access key does not exist.
	 */
	AKY0001E_ACCESS_KEY_NOT_FOUND,
	/**
	 * A new access key has been created.
	 */
	AKY0002I_ACCESS_KEY_CREATED,
	/**
	 * An access key has been removed.
	 */
	AKY0003I_ACCESS_KEY_REMOVED,
	/**
	 * The access key description has been updated.
	 */
	AKY0004I_ACCESS_METADATA_UPDATED, 
	/**
	 * An access key with the given name already exists.
	 */
	AKY0005E_DUPLICATE_KEY_NAME, 
	/**
	 * A unknown database error occured.
	 */
	AKY0006E_DATABASE_ERROR,
	/**
	 * The given access key has an invalid signature.
	 */
	AKY0100E_INVALID_ACCESSKEY,
	/**
	 * The given access key is malformed.
	 */
	AKY0101E_MALFORMED_ACCESSKEY,
	/**
	 * Cannot create the access key verifier due to a configuration issue.
	 */
	AKY0102E_CANNOT_CREATE_VERIFIER,
	/**
	 * Cannot sign the access key due to a configuration issue.
	 */
	AKY0103E_CANNOT_SIGN_ACCESSKEY;
	
	private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("AccesskeyMessages");
	
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
