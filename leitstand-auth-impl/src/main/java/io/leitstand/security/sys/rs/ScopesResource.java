package io.leitstand.security.sys.rs;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.util.SortedSet;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import io.leitstand.commons.rs.Public;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.sys.service.ResourceScopesService;


/**
 * REST resource to list all known resource scopes.
 */
@Resource
@Public
@Path("/auth/scopes")
@Produces(APPLICATION_JSON)
public class ScopesResource {

	@Inject
	private ResourceScopesService scopes;
	
	/**
	 * Returns all existing resource scopes in alphabetical order. 
	 * @return set of resource scopes in alphabetical order
	 */
	@GET
	public SortedSet<String> getScopes(){
		return scopes.getResourceScopes();
	}
	
	
}
