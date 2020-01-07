/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;

import io.leitstand.testing.it.JpaIT;

public class UsersIT extends JpaIT{

	@Override
	protected Properties getConnectionProperties() throws IOException {
		Properties properties = new Properties();
		properties.load(ClassLoader.getSystemResourceAsStream("users-it.properties"));
		return properties;
	}
	
	@Override
	protected void initDatabase(DataSource ds) throws SQLException{
		try(Connection c = ds.getConnection()){
			c.createStatement().execute("CREATE SCHEMA AUTH");
			c.createStatement().execute("CREATE SCHEMA LEITSTAND");
		}
	}
	
	@Override
	protected String getPersistenceUnitName() {
		return "users";
	}

}
