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
package io.leitstand.security.sso.oidc.oauth2;

import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static java.util.Base64.getEncoder;

import java.util.Base64;
import java.util.Date;

import javax.inject.Inject;

import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.crypto.MasterSecret;

/**
 * The default <code>RefreshTokenStore</code> stores the refresh token protected by the {@link MasterSecret} in the Leitstand database.
 */
@Service
public class DefaultRefreshTokenStore implements RefreshTokenStore{

	@Inject
	@Oauth2
	private Repository repository;
	
	@Inject
	private MasterSecret masterSecret;
	
	protected DefaultRefreshTokenStore() {
		// CDI
	}
	
	/**
	 * Creates a new default <code>RefreshTokenStore</code>.
	 * @param repository the token repository
	 * @param masterSecret the master secret to protect the refresh tokens.
	 */
	public DefaultRefreshTokenStore(Repository repository, MasterSecret masterSecret) {
		this.repository = repository;
		this.masterSecret = masterSecret;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void storeRefreshToken(String sub, String refreshToken, Date expiryDate) {
		byte[] encryptedToken = masterSecret.encrypt(toUtf8Bytes(refreshToken));
		String encryptedToken64 = getEncoder().encodeToString(encryptedToken);
		RefreshTokenStoreEntry entry = new RefreshTokenStoreEntry(sub,encryptedToken64, expiryDate);
		repository.merge(entry);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getRefreshToken(String sub) {
		RefreshTokenStoreEntry entry = repository.find(RefreshTokenStoreEntry.class, sub);
		if(entry != null && ! entry.isExpired()) {
			String encryptedToken64 = entry.getRefreshToken();
			byte[] encryptedToken = Base64.getDecoder().decode(encryptedToken64);
			return fromUtf8Bytes(masterSecret.decrypt(encryptedToken));
		}
		return null;
	}

}
