/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import static io.leitstand.security.auth.UserId.randomUserId;
import static io.leitstand.security.auth.UserName.userName;
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
			   .withRoles("Operator")
			   .build();
	}
	
}