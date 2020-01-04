/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.login.log.rs;

import static io.leitstand.commons.model.ObjectUtil.asSet;

import java.util.Set;

import javax.enterprise.context.Dependent;

import io.leitstand.commons.rs.ApiResourceProvider;

/**
 * User login audit log REST API resource provider.
 */
@Dependent
public class UserLoginAuditLogResources implements ApiResourceProvider{

	/**
	 * Returns the user login audit log REST API resource classes.
	 */
	@Override
	public Set<Class<?>> getResources() {
		return asSet(UserLoginAuditLogResource.class);
	}

}