package io.leitstand.security.sys.service;

import java.util.SortedSet;

/**
 * The <code>ResourceScopesService</code> returns an alphabetically sorted set of existing resource scopes.
 */
public interface ResourceScopesService {

	/**
	 * Returns an unmodifiable alphabetically sorted set of existing resource scopes.
	 * @return an unmodifiable alphabetically sorted set of existing resource scopes.
	 */
	SortedSet<String> getResourceScopes();
}
