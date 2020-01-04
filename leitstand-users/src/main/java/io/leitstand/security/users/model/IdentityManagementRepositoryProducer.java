/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Disposes;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceUnit;
import javax.transaction.TransactionScoped;

import io.leitstand.commons.model.Repository;

/**
 * The producer for the repository of the built-in identity management module.
 */
@Dependent
public class IdentityManagementRepositoryProducer {

	@PersistenceUnit(unitName="users")
	private EntityManagerFactory em;
	
	/**
	 * Creates the repository for the built-in identity management module.
	 * @return the identity management repository.
	 */
	@Produces
	@IdentityManagement
	@TransactionScoped
	public Repository identityManagementRepository() {
		return new Repository(em.createEntityManager());
	}
	
	
	public void closeRepository(@Disposes @IdentityManagement Repository repository) {
		repository.close();
	}
	
}
