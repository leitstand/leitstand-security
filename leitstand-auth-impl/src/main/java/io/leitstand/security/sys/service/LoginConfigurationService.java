package io.leitstand.security.sys.service;

/**
 * The <code>LoginConfigurationService</code> provides access to the current login configuration.
 *
 */
public interface LoginConfigurationService {


	/**
	 * Returns the current login configuration.
	 * @return the current login configuration.
	 */
	public LoginConfiguration getLoginConfiguration();
	
}
