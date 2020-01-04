/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import static io.leitstand.security.users.model.Role.findAllRoles;
import static io.leitstand.security.users.service.RoleData.newRoleData;
import static java.util.stream.Collectors.toList;

import java.util.List;

import javax.inject.Inject;

import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.users.service.RoleData;
import io.leitstand.security.users.service.RoleService;

/**
 * The stateless, transactional, default {@link RoleService} implementation.
 */
@Service
public class DefaultRoleService implements RoleService {
	
	@Inject
	@IdentityManagement
	private Repository repository;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<RoleData> getRoles() {
		return repository.execute(findAllRoles())
						 .stream()
						 .map(r -> newRoleData()
								   .withName(r.getName())
								   .withDescription(r.getDescription())
								   .build())
						 .collect(toList());
	}
	
}