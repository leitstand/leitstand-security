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

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Disposes;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceUnit;
import javax.transaction.TransactionScoped;

import io.leitstand.commons.model.Repository;

/**
 * <code>Repository</code> CDI producer for the access-key management module.
 */
@Dependent
public class AccessKeysRepositoryProducer {

	@PersistenceUnit(unitName="accesskeys")
	private EntityManagerFactory emf;
	
	/**
	 * Creates the repository for the access-key management module.
	 * @return the access-key management repository
	 */
	@Produces
	@TransactionScoped
	@AccessKeys
	public Repository identityManagementRepository() {
		return new Repository(emf.createEntityManager());
	}
	
	/**
	 * Closes the access-key management repository when the server gets stopped in order to free all allocated database resources like database connections for example.
	 * @param repository the repostory to be closed
	 */
	public void closeRepository(@Disposes @AccessKeys Repository repository) {
		repository.close();
	}
	
}
