/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.rs;

import static io.leitstand.security.auth.Role.ADMINISTRATOR;
import static io.leitstand.security.auth.Role.SYSTEM;
import static java.lang.String.format;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.created;

import java.net.URI;
import java.util.List;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import io.leitstand.commons.messages.Messages;
import io.leitstand.security.users.service.UserReference;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSubmission;

/**
 * The REST API resource to query for users or add new user accounts.
 */
@RequestScoped
@Path("/users")
@Produces(APPLICATION_JSON)
public class UsersResource {

	@Inject
	private Messages messages;
	
	@Inject
	private UserService service;
	
	/**
	 * Returns all users matching the given filter expression.
	 * @param filter - the POSIX filter expression
	 * @return all users matching the given filter expression or an empty list if no users were found.
	 */
	@GET
	@Path("/")
	@Produces(APPLICATION_JSON)
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public List<UserReference> findUsers(@QueryParam("filter") String filter){
		return service.findUsers(filter);
	}

	/**
	 * Creates a new user account and assigns a UUID to the account.
	 * @param user - the user account settings.
	 * @return messages to explain the outcome of the operation
	 */
	@POST
	@Path("/")
	@RolesAllowed({ADMINISTRATOR,SYSTEM})
	public Response storeUserSettings(@Valid UserSubmission user) {
		service.addUser(user);
		return created(URI.create(format("/api/v1/users/%s",
										 user.getUserId())))
			   .entity(messages)
			   .build();
	}
	
}