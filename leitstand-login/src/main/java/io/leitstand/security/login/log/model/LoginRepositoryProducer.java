/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.login.log.model;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Disposes;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceUnit;
import javax.transaction.TransactionScoped;

import io.leitstand.commons.model.Repository;

/**
 * The producer for the login audit log module repository.
 */
@Dependent
public class LoginRepositoryProducer {

	@PersistenceUnit(unitName="login")
	private EntityManagerFactory em;
	
	/**
	 * Produces a {@link Repository} for the login audit log module.
	 * @return the authentication module repository.
	 */
	@Produces
	@TransactionScoped
	@Login
	public Repository authenticationRepository() {
		return new Repository(em.createEntityManager());
	}
	
	public void closeRepository(@Disposes @Login Repository repository) {
		repository.close();
	}
	
}