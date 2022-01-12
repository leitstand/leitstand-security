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
package io.leitstand.security.users.rs;

import static io.leitstand.commons.model.ObjectUtil.isDifferent;
import static io.leitstand.commons.model.Patterns.UUID_PATTERN;
import static io.leitstand.commons.rs.ReasonCode.VAL0003E_IMMUTABLE_ATTRIBUTE;
import static io.leitstand.security.users.rs.Scopes.ADM;
import static io.leitstand.security.users.rs.Scopes.ADM_READ;
import static io.leitstand.security.users.rs.Scopes.ADM_USER;
import static io.leitstand.security.users.rs.Scopes.ADM_USER_READ;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import io.leitstand.commons.ConflictException;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.auth.Scopes;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.users.service.UserId;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

/**
 * The REST API resource to manage a user account.
 */
@Resource
@Path("/users")
@Consumes(APPLICATION_JSON)
@Produces(APPLICATION_JSON)
public class UserResource {
	
	@Inject
	private UserService service;
	
	@Inject
	private Messages messages;
	
	
	/**
	 * Returns the user account settings.
	 * @param userName the login ID 
	 * @return the user account settings.
	 */
	@GET
	@Path("/me")
	public UserSettings getUserSettings() {
		return service.getAuthenticatedUser();
	}
	
	/**
	 * Returns the user account settings.
	 * @param userName the login ID 
	 * @return the user account settings.
	 */
	@GET
	@Path("/{user}")
	@Scopes({ADM, ADM_USER, ADM_READ, ADM_USER_READ})
	public UserSettings getUserSettings(@Valid @PathParam("user") UserName userName) {
		return service.getUser(userName);
	}
	
	/**
	 * Returns the user account settings.
	 * @param userId the account UUID
	 * @return the user account settings.
	 */
	@GET
	@Path("/{user:"+UUID_PATTERN+"}")
	@Scopes({ADM, ADM_USER, ADM_READ, ADM_USER_READ})
	public UserSettings getUserSettings(@PathParam("user") UserId userId) {
		return service.getUser(userId);
	}


	/**
	 * Stores a user account by either updating an existing account or creating a new account.
	 * @param userId the immutable user account UUID
	 * @param userId the user settings
	 * @return messages to explain the outcome of the operation, 
	 * 		   wrapped in a response object to set the HTTP status code properly,
	 * 		   i.e. <code>201 Created</code>, if a new user account was created or 
	 * 				<code>200 Ok</code>, if an existing user account was updated.
	 */
	@PUT
	@Path("/{user:"+UUID_PATTERN+"}")
	@Scopes({ADM, ADM_USER})
	public Messages storeUserSettings(@PathParam("user") UserId userId, 
									  @Valid UserSettings settings) {
		
		if(isDifferent(userId, settings.getUserId())) {
			throw new ConflictException(VAL0003E_IMMUTABLE_ATTRIBUTE, userId);
		}
		service.storeUserSettings(settings);
		return messages;
		
	}

	
	/**
	 * Changes an user's password.
	 * The user must provide their current password in order to update the password.
	 * @param userId the user login ID
	 * @param passwd the password change request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{user:"+UUID_PATTERN+"}/_passwd")
	@Scopes({ADM, ADM_USER})
	public Messages storePassword(@Valid @PathParam("user") UserId userId, 
							      @Valid ChangePasswordRequest passwd) {
		service.setPassword(userId, 
							passwd.getPassword(),
							passwd.getNewPassword(),
							passwd.getConfirmedPassword());
		return messages;
	}
	
	/**
	 * Changes a user's password.
	 * The user must provide their current password in order to update the password.
	 * @param userName the user login ID
	 * @param passwd the password change request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{user}/_passwd")
	@Scopes({ADM, ADM_USER})
	public Messages storePassword(@Valid @PathParam("user") UserName userName, 
							      @Valid ChangePasswordRequest passwd) {
		service.setPassword(userName, 
							passwd.getPassword(),
							passwd.getNewPassword(),
							passwd.getConfirmedPassword());
		return messages;
	}


	/**
	 * Resets the user account password to the specified password.
	 * This operation requires administrator privileges.
	 * @param userId the user account ID
	 * @param passwd the reset password request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{user:"+UUID_PATTERN+"}/_reset")
	@Scopes({ADM, ADM_USER})
	public Messages reset(@PathParam("user") UserId userId, 
						  @Valid ResetPasswordRequest passwd) {
		service.resetPassword(userId, 
							  passwd.getNewPassword(),
							  passwd.getConfirmedPassword());
		return messages;
	}
	
	
	/**
	 * Resets the user account password to the specified password.
	 * This operation requires administrator privileges.
	 * @param userName the user name
	 * @param passwd the reset password request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{user}/_reset")
	@Scopes({ADM, ADM_USER})
	public Messages reset(@Valid @PathParam("user") UserName userName, 
						  @Valid ResetPasswordRequest passwd) {
		service.resetPassword(userName, 
							  passwd.getNewPassword(),
							  passwd.getConfirmedPassword());
		return messages;
	}
	
	/**
	 * Removes a user from the user repository.
	 * This operation requires administrator privileges.
	 * @param userId the name of the user to be removed
	 * @return messages to explain the outcome of the operation
	 */
	@DELETE
	@Path("/{user:"+UUID_PATTERN+"}")
	@Scopes({ADM, ADM_USER})
	public Messages removeUser(@PathParam("user") UserId userId) {
		service.removeUser(userId);
		return messages;
	}
	
	
	/**
	 * Removes a user from the user repository.
	 * This operation requires administrator privileges.
	 * @param userName the user ID to be removed.
	 * @return messages to explain the outcome of the operation
	 */
	@DELETE
	@Path("/{user}")
	@Scopes({ADM, ADM_USER})
	public Messages removeUser(@Valid @PathParam("user") UserName userName) {
		service.removeUser(userName);
		return messages;
	}
	
}
