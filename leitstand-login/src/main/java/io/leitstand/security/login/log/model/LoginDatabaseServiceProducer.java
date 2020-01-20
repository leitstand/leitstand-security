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
package io.leitstand.security.login.log.model;

import javax.annotation.Resource;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.sql.DataSource;

import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.model.Repository;

/**
 * The producer for the login audit log module repository.
 */
@Dependent
public class LoginDatabaseServiceProducer {

	@Resource(lookup="java:/jdbc/leitstand")
	private DataSource ds;
	
	/**
	 * Produces a {@link Repository} for the login audit log module.
	 * @return the authentication module repository.
	 */
	@Produces
	@ApplicationScoped
	@Login
	public DatabaseService authenticationDatabaseService() {
		return new DatabaseService(ds);
	}
	
}
