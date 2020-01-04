/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.graylog;

import static io.leitstand.commons.model.ObjectUtil.asSet;

import java.util.Set;

import javax.enterprise.context.Dependent;

import io.leitstand.commons.rs.ApiResourceProvider;

@Dependent
public class GraylogUserResources implements ApiResourceProvider {

	@Override
	public Set<Class<?>> getResources() {
		return asSet(UserRepository.class);
	}

}
