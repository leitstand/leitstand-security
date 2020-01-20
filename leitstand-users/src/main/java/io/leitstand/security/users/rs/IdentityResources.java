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
