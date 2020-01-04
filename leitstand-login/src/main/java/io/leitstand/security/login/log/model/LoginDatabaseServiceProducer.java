/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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

	@Resource(lookup="java:/jdbc/rbms")
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