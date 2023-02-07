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

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.users.service.RoleName.roleName;
import static io.leitstand.security.users.service.UserId.randomUserId;
import static io.leitstand.security.users.service.UserSettings.newUserSettings;

import java.security.Principal;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.users.service.UserSettings;

final class UserSettingsMother {


	public static UserSettings newOperator(Principal principal) {
		return newOperator(principal.getName());
	}
	
	public static UserSettings newOperator(String userName) {
		return newOperator(userName(userName));
	}
	
	public static UserSettings newOperator(UserName userName) {
		return newUserSettings()
			   .withUserId(randomUserId())
			   .withUserName(userName)
			   .withRoles(roleName("Operator"))
			   .build();
	}
	
}
