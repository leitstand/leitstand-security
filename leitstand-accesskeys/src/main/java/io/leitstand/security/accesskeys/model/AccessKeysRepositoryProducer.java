/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.model;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Disposes;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceUnit;
import javax.transaction.TransactionScoped;

import io.leitstand.commons.model.Repository;
import io.leitstand.security.accesskeys.auth.AccessKeys;

/**
 * The producer for the repository of the built-in identity management module.
 */
@Dependent
public class AccessKeysRepositoryProducer {

	@PersistenceUnit(unitName="accesskeys")
	private EntityManagerFactory emf;
	
	/**
	 * Creates the repository for the built-in identity management module.
	 * @return the identity management repository.
	 */
	@Produces
	@TransactionScoped
	@AccessKeys
	public Repository identityManagementRepository() {
		return new Repository(emf.createEntityManager());
	}
	
	public void closeRepository(@Disposes @AccessKeys Repository repository) {
		repository.close();
	}
	
}
