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
package io.leitstand.security.auth.login;

import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;
import static javax.json.Json.createReader;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;

import java.io.IOException;
import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.user.LoginManager;

@Dependent
public class DefaultLoginManager implements LoginManager{

	private static final Logger LOG  = getLogger(DefaultLoginManager.class.getName());

	@Inject
	private IdentityStore is;
	
	/**
	 * Reads the JSON body of a login request to create a <code>UsernamePasswordCredential</code> instance.
	 * @param reader the JSON reader of the login request body
	 * @return the created <code>UsernamePasswordCredential</code>.
	 */
	static UsernamePasswordCredential readCredentials(JsonReader reader) {
		JsonObject request 	= reader.readObject();
		String	   userName  	= request.getString("user_name");
		Password   password = new Password(request.getString("password"));
		return new UsernamePasswordCredential(userName, password);
	}
	
	/**
	 * Processes a login request and logs the login attempt outcome.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return <code>INVALID_RESULT</code> if the provided credentials were invalid, 
	 * otherwise information about the authenticated user and its assigned roles
	 */
	@Override
	public CredentialValidationResult login(HttpServletRequest request, 
										 	HttpServletResponse response) {
		
		try(JsonReader reader = createReader(request.getReader())){
			
			// Read and verify credential data
			UsernamePasswordCredential credential = readCredentials(reader);
			return is.validate(credential);

		} catch(JsonException | IOException  e) {
			LOG.fine(() -> format("Cannot parse credentials: %s",e.getMessage()));
			return INVALID_RESULT;
		}
	}
	
}
