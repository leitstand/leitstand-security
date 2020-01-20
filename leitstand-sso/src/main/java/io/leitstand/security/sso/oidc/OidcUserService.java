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
package io.leitstand.security.sso.oidc;

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.security.users.model.Role.findRoleByName;
import static io.leitstand.security.users.model.User.findUserByName;
import static io.leitstand.security.users.service.ReasonCode.IDM0001I_USER_STORED;
import static java.lang.String.format;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.inject.Inject;

import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.users.model.IdentityManagement;
import io.leitstand.security.users.model.Role;
import io.leitstand.security.users.model.User;

@Service
public class OidcUserService {
	
	private static final Logger LOG = Logger.getLogger(OidcUserService.class.getName());

	@Inject
	private Messages messages;
	
	@Inject
	@IdentityManagement
	private Repository repository;
	
	@Inject
	private OidcConfig config;
	
	
	public Set<String> storeUser(UserInfo userInfo) {
		UserName userName = userInfo.getUserName();
		User user = repository.execute(findUserByName(userName));
		if(user == null) {
			user = new User(userName);
			repository.add(user);
		}
		user.setGivenName(userInfo.getGivenName());
		user.setFamilyName(userInfo.getFamilyName());
		user.setEmailAddress(userInfo.getEmail());
		
		UserId userId = user.getUserId();
		LOG.fine(() -> format("%s: User %s (%s) stored.",
					          IDM0001I_USER_STORED.getReasonCode(),
					          userName, 
					          userId));
		messages.add(createMessage(IDM0001I_USER_STORED, 
				     userId,
				     userName));

		if(config.isCustomRolesClaimEnabled() && userInfo.getRoles() != null) {
			user.setRoles(loadRoles(userInfo.getRoles()));
		}
		return user.getRoleNames();
	}
	
	private List<Role> loadRoles(Set<String> roleNames) {
		List<Role> roles = new LinkedList<>();
		for(String roleName : roleNames) {
			Role role = repository.execute(findRoleByName(roleName));
			if(role == null) {
				continue;
			}
			roles.add(role);
		}
		return roles;
	}

	
}
