/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.rs;

import static io.leitstand.commons.model.ObjectUtil.asSet;

import java.util.Set;

import javax.enterprise.context.Dependent;

import io.leitstand.commons.rs.ApiResourceProvider;

@Dependent
public class AuthResources implements ApiResourceProvider{

	@Override
	public Set<Class<?>> getResources() {
		return asSet(LoginResource.class, 
					 LogoutResource.class);
	}

}
