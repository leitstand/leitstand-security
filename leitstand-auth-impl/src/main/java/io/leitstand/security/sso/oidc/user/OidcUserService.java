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
package io.leitstand.security.sso.oidc.user;

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.security.users.model.User.findUserByName;
import static io.leitstand.security.users.service.ReasonCode.IDM0001I_USER_STORED;
import static io.leitstand.security.users.service.UserId.userId;
import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;

import java.util.logging.Logger;

import javax.inject.Inject;

import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.sso.oidc.service.OidcUserInfo;
import io.leitstand.security.users.model.IdentityManagement;
import io.leitstand.security.users.model.User;

@Service
public class OidcUserService {
	
	private static final Logger LOG = getLogger(OidcUserService.class.getName());

	private Messages messages;
	
	private Repository repository;
	
	protected OidcUserService() {
		// CDI
	}
	
	@Inject
	protected OidcUserService(@IdentityManagement Repository repository, Messages messages) {
		this.repository = repository;
		this.messages = messages;
	}
	
	
	public void storeUser(OidcUserInfo userInfo) {
		UserName userName = userInfo.getUserName();
		User user = repository.execute(findUserByName(userName));
		if(user == null) {
			user = new User(userId(userInfo.getSub())  ,userName);
			repository.add(user);
		}
		user.setGivenName(userInfo.getGivenName());
		user.setFamilyName(userInfo.getFamilyName());
		user.setEmailAddress(userInfo.getEmail());
		
		LOG.fine(() -> format("%s: User %s stored.",
					          IDM0001I_USER_STORED.getReasonCode(),
					          userName));
		messages.add(createMessage(IDM0001I_USER_STORED, 
					 user.getUserId(),
				     userName));

	}
	
}
