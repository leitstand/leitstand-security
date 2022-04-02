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
package io.leitstand.security.users.model;

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.security.users.model.Role.findAllRoles;
import static io.leitstand.security.users.model.Role.findRoleById;
import static io.leitstand.security.users.model.Role.findRoleByName;
import static io.leitstand.security.users.service.ReasonCode.IDM0006E_ROLE_NOT_FOUND;
import static io.leitstand.security.users.service.ReasonCode.IDM0010I_ROLE_REMOVED;
import static io.leitstand.security.users.service.ReasonCode.IDM0011I_ROLE_STORED;
import static io.leitstand.security.users.service.ReasonCode.IDM0100E_CANNOT_ADD_SYSTEM_ROLE;
import static io.leitstand.security.users.service.ReasonCode.IDM0101E_CANNOT_UPDATE_SYSTEM_ROLE;
import static io.leitstand.security.users.service.ReasonCode.IDM0102E_CANNOT_REMOVE_SYSTEM_ROLE;
import static io.leitstand.security.users.service.RoleSettings.newRoleSettings;
import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;
import static java.util.stream.Collectors.toList;

import java.util.List;
import java.util.logging.Logger;

import javax.inject.Inject;

import io.leitstand.commons.ConflictException;
import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Query;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.users.service.RoleId;
import io.leitstand.security.users.service.RoleName;
import io.leitstand.security.users.service.RoleService;
import io.leitstand.security.users.service.RoleSettings;

/**
 * Default {@link RoleService} implementation.
 */
@Service
public class DefaultRoleService implements RoleService {
	
	private static final Logger LOG = getLogger(RoleService.class.getName());
	
			
	private Repository repository;
	
	private Messages messages;
	

	protected DefaultRoleService() {
		// CDI
	}
	
	@Inject
	protected DefaultRoleService(@IdentityManagement Repository repository, Messages messages){
		this.repository = repository;
		this.messages = messages;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<RoleSettings> getRoles() {
		return repository.execute(findAllRoles())
						 .stream()
						 .map(r -> newRoleSettings()
								   .withRoleId(r.getRoleId())
								   .withRoleName(r.getRoleName())
								   .withDescription(r.getDescription())
								   .withScopes(r.getScopes())
								   .build())
						 .collect(toList());
	}

	@Override
	public boolean storeRole(RoleSettings settings) {
		Role role = repository.execute(findRoleById(settings.getRoleId()));
		boolean created = false;
		if (role == null) {
			if(settings.isSystemRole()) {
				LOG.info(()->format("%s: Cannot update system role %s",
							 IDM0101E_CANNOT_UPDATE_SYSTEM_ROLE.getReasonCode(),
							 settings.getRoleName()));
				throw new UnprocessableEntityException(IDM0100E_CANNOT_ADD_SYSTEM_ROLE,
													   settings.getRoleName());
			}
			
			role = new Role(settings.getRoleId(),settings.getRoleName());
			repository.add(role);
			created = true;
		}
	
		if(role.isSystemRole()) {
			RoleName roleName = role.getRoleName();
			LOG.info(()->format("%s: Cannot update system role %s",
							    IDM0101E_CANNOT_UPDATE_SYSTEM_ROLE.getReasonCode(),
							    roleName));
			throw new ConflictException(IDM0101E_CANNOT_UPDATE_SYSTEM_ROLE,role.getRoleName());
		}
	
		
		role.setRoleName(settings.getRoleName());
		role.setDescription(settings.getDescription());
		role.setScopes(settings.getScopes());
		
		LOG.info(() -> format("%s: Stored role %s with assigned scopes: %s",
							  IDM0011I_ROLE_STORED.getReasonCode(),
							  settings.getRoleName(),
							  settings.getScopes()));
		
		messages.add(createMessage(IDM0011I_ROLE_STORED, settings.getRoleName()));
		
		return created;
	}

	@Override
	public void removeRole(RoleId roleId) {
		removeRole(findRoleById(roleId));
		
	}

	private void removeRole(Query<Role> query) {
		Role role = repository.execute(query);
		if (role != null) {
			if(role.isSystemRole()) {
				throw new ConflictException(IDM0102E_CANNOT_REMOVE_SYSTEM_ROLE, role.getRoleName());
			}
			
			repository.remove(role);
			LOG.info(() -> format("%s: Removed role %s", 
								  IDM0010I_ROLE_REMOVED.getReasonCode(),
								  role.getRoleName())) ;
			messages.add(createMessage(IDM0010I_ROLE_REMOVED, 
									   role.getRoleName()));
		}
	}

	@Override
	public void removeRole(RoleName roleName) {
		removeRole(findRoleByName(roleName));
	}

	@Override
	public RoleSettings getRole(RoleId roleId) {
		Role role = repository.execute(findRoleById(roleId));
		if(role != null) {
			return settingsOf(role);
		}
		LOG.fine(() -> format("%s: Role %s not found.",
							 IDM0006E_ROLE_NOT_FOUND.getReasonCode(),
							 roleId));
		throw new EntityNotFoundException(IDM0006E_ROLE_NOT_FOUND,roleId);
	}

	@Override
	public RoleSettings getRole(RoleName roleName) {
		Role role = repository.execute(findRoleByName(roleName));
		if(role != null) {
			return settingsOf(role);
		}
		LOG.fine(() -> format("%s: Role %s not found.",
							 IDM0006E_ROLE_NOT_FOUND.getReasonCode(),
							 roleName));
		throw new EntityNotFoundException(IDM0006E_ROLE_NOT_FOUND,roleName);
	}
	
	private RoleSettings settingsOf(Role role) {
		return newRoleSettings()
			   .withRoleId(role.getRoleId())
			   .withRoleName(role.getRoleName())
			   .withDescription(role.getDescription())
			   .withScopes(role.getScopes())
			   .withSystemRole(role.isSystemRole())
			   .build();
		
	}
	
}
