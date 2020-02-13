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

import javax.inject.Inject;

import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.sso.oauth2.RefreshTokenStore;

@Service
public class DefaultRefreshTokenStore implements RefreshTokenStore{

	@Inject
	@Oauth2
	private Repository repository;
	
	protected DefaultRefreshTokenStore() {
		// CDI
	}
	
	public DefaultRefreshTokenStore(Repository repository) {
		this.repository = repository;
	}

	@Override
	public void storeRefreshToken(String sub, String refreshToken64) {
		RefreshTokenStoreEntry entry = new RefreshTokenStoreEntry(sub,refreshToken64);
		repository.merge(entry);
	}

	@Override
	public String getRefreshToken(String sub) {
		RefreshTokenStoreEntry entry = repository.find(RefreshTokenStoreEntry.class, sub);
		if(entry != null) {
			return entry.getRefreshToken();
		}
		return null;
	}

}
