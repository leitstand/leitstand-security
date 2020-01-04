/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.rs;

import static io.leitstand.commons.model.ObjectUtil.asSet;

import java.util.Set;

import javax.enterprise.context.Dependent;

import io.leitstand.commons.rs.ApiResourceProvider;
import io.leitstand.security.sso.oauth2.AuthorizationService;

@Dependent
public class SsoResources implements ApiResourceProvider{

	@Override
	public Set<Class<?>> getResources() {
		return asSet(AuthorizationService.class);
	}

}