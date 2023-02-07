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
package io.leitstand.security.sso.oidc;

import static java.util.ResourceBundle.getBundle;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

/**
 * Enumeration of OpenID/Connect-related Leitstand reason codes.
  */
public enum ReasonCode implements Reason{

    /**
     * Cannot create an access token.
     */
	OID0001E_CANNOT_CREATE_ACCESS_TOKEN,
	/**
	 * Cannot read the user information of an authenticated user.
	 */
	OID0002E_CANNOT_READ_USER_INFO,
	/**
	 * Created a new session after a successful login attempt.
	 */
	OID0003I_SESSION_CREATED,
	/**
	 * Cannot refresh an access token. Typically the refresh token is also expired.
	 */
	OID0004E_CANNOT_REFRESH_ACCESS_TOKEN,
	/**
	 * Cannot validate a certificate due to a broken certificate chain.
	 */
	OID0005E_CERTIFICATE_CHAIN_ERROR,
    /**
     * Invalid or expired access token.
     */
	OID0006E_INVALID_ACCESS_TOKEN,
	/**
	 * Cannot read JSON Web Key Set.
	 */
	OID0007E_CANNOT_READ_JWKS;
	
	private static final ResourceBundle MESSAGES = getBundle("OidcMessages");
	
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
