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
