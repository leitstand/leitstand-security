/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import javax.annotation.Resource;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.sql.DataSource;

import io.leitstand.commons.db.DatabaseService;

/**
 * The producer for the repository of the built-in identity management module.
 */
@Dependent
public class IdentityManagementDatabaseServiceProducer {

	@Resource(lookup="java:/jdbc/rbms")
	private DataSource ds;
	
	/**
	 * Creates the repository for the built-in identity management module.
	 * @return the identity management repository.
	 */
	@Produces
	@ApplicationScoped
	@IdentityManagement
	public DatabaseService identityManagementDatabaseService() {
		return new DatabaseService(ds);
	}
	
}
