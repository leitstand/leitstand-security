/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.rs;

import static io.leitstand.commons.model.ObjectUtil.isDifferent;
import static io.leitstand.commons.model.Patterns.UUID_PATTERN;
import static io.leitstand.commons.rs.ReasonCode.VAL0003E_IMMUTABLE_ATTRIBUTE;
import static io.leitstand.security.auth.Role.ADMINISTRATOR;
import static io.leitstand.security.auth.Role.SYSTEM;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import io.leitstand.commons.ConflictException;
import io.leitstand.commons.messages.Messages;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

/**
 * The REST API resource to manage a user account.
 */
@RequestScoped
@Path("/users")
@Produces(APPLICATION_JSON)
public class UserResource {
	
	@Inject
	private UserService service;
	
	@Inject
	private Messages messages;
	
	
	/**
	 * Returns the user account settings.
	 * @param userId - the login ID 
	 * @return the user account settings.
	 */
	@GET
	@Path("/me")
	public UserSettings getUserSettings() {
		return service.getAuthenticatedUser();
	}
	
	/**
	 * Returns the user account settings.
	 * @param userId - the login ID 
	 * @return the user account settings.
	 */
	@GET
	@Path("/{user}")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public UserSettings getUserSettings(@Valid @PathParam("user") UserId userId) {
		return service.getUser(userId);
	}
	
	/**
	 * Returns the user account settings.
	 * @param uuid - the account UUID
	 * @return the user account settings.
	 */
	@GET
	@Path("/{uuid:"+UUID_PATTERN+"}")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public UserSettings getUserSettings(@PathParam("uuid") String uuid) {
		return service.getUser(uuid);
	}


	/**
	 * Stores a user account by either updating an existing account or creating a new account.
	 * @param uuid - the immutable user account UUID
	 * @param user - the user settings
	 * @return messages to explain the outcome of the operation, 
	 * 		   wrapped in a response object to set the HTTP status code properly,
	 * 		   i.e. <code>201 Created</code>, if a new user account was created or 
	 * 				<code>200 Ok</code>, if an existing user account was updated.
	 */
	@PUT
	@Path("/{uuid:"+UUID_PATTERN+"}")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Messages storeUserSettings(@PathParam("uuid") String uuid, 
									  @Valid UserSettings settings) {
		
		if(isDifferent(uuid, settings.getUuid())) {
			throw new ConflictException(VAL0003E_IMMUTABLE_ATTRIBUTE, uuid);
		}
		service.storeUserSettings(settings);
		return messages;
		
	}

	
	/**
	 * Changes an user's password.
	 * The user must provide their current password in order to update the password.
	 * @param userId - the user login ID
	 * @param passwd - the password change request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{uuid:"+UUID_PATTERN+"}/_passwd")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Messages storePassword(@Valid @PathParam("uuid") String uuid, 
							      @Valid ChangePasswordRequest passwd) {
		service.setPassword(uuid, 
							passwd.getPassword(),
							passwd.getNewPassword(),
							passwd.getConfirmedPassword());
		return messages;
	}
	
	/**
	 * Changes a user's password.
	 * The user must provide their current password in order to update the password.
	 * @param userId - the user login ID
	 * @param passwd - the password change request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{user}/_passwd")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Messages storePassword(@Valid @PathParam("user") UserId userId, 
							      @Valid ChangePasswordRequest passwd) {
		service.setPassword(userId, 
							passwd.getPassword(),
							passwd.getNewPassword(),
							passwd.getConfirmedPassword());
		return messages;
	}


	/**
	 * Resets the user account password to the specified password.
	 * This operation requires administrator privileges.
	 * @param userId - the user's ID
	 * @param passwd - the reset password request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{uuid:"+UUID_PATTERN+"}/_reset")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Messages reset(@PathParam("uuid") String uuid, 
						  @Valid ResetPasswordRequest passwd) {
		service.resetPassword(uuid, 
							  passwd.getNewPassword(),
							  passwd.getConfirmedPassword());
		return messages;
	}
	
	
	/**
	 * Resets the user account password to the specified password.
	 * This operation requires administrator privileges.
	 * @param userId - the user's ID
	 * @param passwd - the reset password request
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/{user}/_reset")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Messages reset(@Valid @PathParam("user") UserId userId, 
						  @Valid ResetPasswordRequest passwd) {
		service.resetPassword(userId, 
							  passwd.getNewPassword(),
							  passwd.getConfirmedPassword());
		return messages;
	}
	
	/**
	 * Removes a user from the user repository.
	 * This operation requires administrator privileges.
	 * @param userId - the user ID to be removed.
	 * @return messages to explain the outcome of the operation
	 */
	@DELETE
	@Path("/{uuid:"+UUID_PATTERN+"}")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Messages removeUser(@PathParam("uuid") String uuid) {
		service.removeUser(uuid);
		return messages;
	}
	
	
	/**
	 * Removes a user from the user repository.
	 * This operation requires administrator privileges.
	 * @param userId - the user ID to be removed.
	 * @return messages to explain the outcome of the operation
	 */
	@DELETE
	@Path("/{user}")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Messages removeUser(@Valid @PathParam("user") UserId userId) {
		service.removeUser(userId);
		return messages;
	}
	
}
