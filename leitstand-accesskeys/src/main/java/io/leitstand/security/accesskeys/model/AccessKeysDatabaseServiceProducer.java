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
package io.leitstand.security.accesskeys.model;

import javax.annotation.Resource;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.sql.DataSource;

import io.leitstand.commons.db.DatabaseService;

/**
 * <code>DatabaseService</code> CDI producer for the access-key management module. 
 */
@Dependent
public class AccessKeysDatabaseServiceProducer {

	@Resource(lookup="java:/jdbc/leitstand")
	private DataSource ds;
	
	/**
	 * Creates a <code>DatabaseService</code> for the access-key management module.
	 * @return the <code>DatabaseService</code> instance of the access key management module
	 */
	@Produces
	@ApplicationScoped
	@AccessKeys
	public DatabaseService identityManagementDatabaseService() {
		return new DatabaseService(ds);
	}
	
}
