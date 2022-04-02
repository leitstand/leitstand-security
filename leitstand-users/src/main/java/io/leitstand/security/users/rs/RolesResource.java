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
import static io.leitstand.commons.rs.Responses.created;
import static io.leitstand.commons.rs.Responses.success;
import static io.leitstand.security.users.rs.Scopes.ADM;
import static io.leitstand.security.users.rs.Scopes.ADM_READ;
import static io.leitstand.security.users.rs.Scopes.ADM_USER;
import static io.leitstand.security.users.rs.Scopes.ADM_USER_READ;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import io.leitstand.commons.ConflictException;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.auth.Scopes;
import io.leitstand.security.users.service.RoleId;
import io.leitstand.security.users.service.RoleName;
import io.leitstand.security.users.service.RoleService;
import io.leitstand.security.users.service.RoleSettings;

/**
 * The REST API resource to query existing roles.
 */
@Resource
@Path("/userroles")
@Scopes({ADM, ADM_USER})
@Consumes(APPLICATION_JSON)
@Produces(APPLICATION_JSON)
public class RolesResource {

	private RoleService service;
	
	private Messages messages;
	
	protected RolesResource() {
		// CDI
	}
	
	@Inject
	protected RolesResource(RoleService service, Messages messages) {
		this.service = service;
		this.messages = messages;
	}
	
	
	/**
	 * Returns all existing roles.
	 * @return all existing roles.
	 */
	@GET
	@Scopes({ADM, ADM_USER, ADM_USER_READ,ADM_READ})
	public List<RoleSettings> getRoles(){
		return service.getRoles();
	}
	
	@GET
	@Path("/{role:"+UUID_PATTERN+"}")
	@Scopes({ADM, ADM_USER, ADM_USER_READ,ADM_READ})
	public RoleSettings getRole(@PathParam("role") RoleId roleId) {
		return service.getRole(roleId);
	}

	@GET
	@Path("/{role}")
	@Scopes({ADM, ADM_USER, ADM_USER_READ,ADM_READ})
	public RoleSettings getRole(@PathParam("role") RoleName roleName) {
		return service.getRole(roleName);
	}

	@PUT
	@Path("/{role:"+UUID_PATTERN+"}")
	public Response storeRole(@PathParam("role") RoleId roleId, 
							  RoleSettings settings) {
		if(isDifferent(roleId, settings.getRoleId())) {
			throw new ConflictException(VAL0003E_IMMUTABLE_ATTRIBUTE, "role_id",settings.getRoleId(),roleId);
		}
		boolean created = service.storeRole(settings);
		if(created) {
			return created(messages,settings.getRoleId());
		}
		return success(messages);
	}

	@POST
	public Response storeRole(RoleSettings settings) {
		return storeRole(settings.getRoleId(),settings);
	}
	
	@DELETE
	@Path("/{role:"+UUID_PATTERN+"}")
	public Response removeRole(@PathParam("role") RoleId roleId) {
		service.removeRole(roleId);
		return success(messages);
	}

	@DELETE
	@Path("/{role}")
	public Response removeRole(@PathParam("role") RoleName roleName) {
		service.removeRole(roleName);
		return success(messages);
	}


}
