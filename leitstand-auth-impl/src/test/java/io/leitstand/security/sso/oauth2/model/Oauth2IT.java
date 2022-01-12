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
package io.leitstand.security.sso.oauth2.model;

import static java.lang.ClassLoader.getSystemResourceAsStream;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;

import io.leitstand.testing.it.JpaIT;

public class Oauth2IT extends JpaIT {

	@Override
	protected Properties getConnectionProperties() throws IOException {
		Properties properties = new Properties();
		properties.load(getSystemResourceAsStream("oauth2-it.properties"));
		return properties;
	}

	/** {@inheritDoc} */
	@Override
	protected void initDatabase(DataSource ds) throws SQLException{
		try (Connection c = ds.getConnection()) {
			// Create empty schemas to enable JPA to create all tables. 
			c.createStatement().execute("CREATE SCHEMA auth;");
		} 
	}
	
	@Override
	protected String getPersistenceUnitName() {
		return "oauth2";
	}

}
