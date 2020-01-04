/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import static io.leitstand.security.users.service.UserSettings.newUserSettings;

import java.security.Principal;
import java.util.UUID;

import io.leitstand.security.auth.UserId;
import io.leitstand.security.users.service.UserSettings;

final class UserSettingsMother {


	public static UserSettings newOperator(Principal principal) {
		return newOperator(principal.getName());
	}
	
	public static UserSettings newOperator(String userId) {
		return newOperator(UserId.valueOf(userId));
	}
	
	public static UserSettings newOperator(UserId userId) {
		return newUserSettings()
			   .withUuid(UUID.randomUUID().toString())
			   .withUserId(userId)
			   .withRoles("Operator")
			   .build();
	}
	
	
}
