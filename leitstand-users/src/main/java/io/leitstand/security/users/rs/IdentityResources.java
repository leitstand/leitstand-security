/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.rs;

import static io.leitstand.commons.model.ObjectUtil.asSet;

import java.util.Set;

import javax.enterprise.context.Dependent;

import io.leitstand.commons.rs.ApiResourceProvider;

/**
 * Exposes all REST API resources of the  built-in identity management
 */
@Dependent
public class IdentityResources implements ApiResourceProvider{

	/**
	 * Returns the REST API resources of the built-in identity management.
	 * @return the REST API resources of the built-in identity management.
	 */
	@Override
	public Set<Class<?>> getResources() {
		return asSet(UsersResource.class,
					 UserResource.class,
					 RolesResource.class);
	}
	
}
