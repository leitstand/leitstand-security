/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.rs;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.util.List;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import io.leitstand.security.users.service.RoleData;
import io.leitstand.security.users.service.RoleService;

/**
 * The REST API resource to query existing roles.
 */
@RequestScoped
@Path("/userroles")
@Produces(APPLICATION_JSON)
public class RolesResource {

	@Inject
	private RoleService service;
	
	
	/**
	 * Returns all existing roles.
	 * @return all existing roles.
	 */
	@GET
	@Path("/")
	public List<RoleData> getRoles(){
		return service.getRoles();
	}
	
}
