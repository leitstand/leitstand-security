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
package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.db.DatabaseService.prepare;
import static io.leitstand.security.accesskeys.model.AccessKey.findByAccessKeyId;
import static io.leitstand.security.auth.accesskeys.AccessKeyId.accessKeyId;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.logging.Logger.getLogger;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.inject.Inject;

import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.accesskeys.service.AccessKeyValidatorService;
import io.leitstand.security.auth.accesskeys.AccessKeyId;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.jwt.Jwt;
import io.leitstand.security.auth.jwt.JwtException;

/**
 * The <code>DefaultAccessKeyValidatorService</code> provides means to test whether an API access key is still valid or has been revoked.
 * This service caches the state of an API access key for 60 seconds, which means that it takes up to 60 seconds until revoking an API 
 * access key take effect.
 */
@Service
public class DefaultAccessKeyValidatorService implements AccessKeyValidatorService{
	
	private static final Logger LOG = getLogger(DefaultAccessKeyValidatorService.class.getName());

	static final class AccessKeyState {
		
		private boolean revoked;
		private long nextCheck;
		
		public boolean isRevoked() {
			return revoked;
		}
		
		void revoked() {
			this.revoked = true;
		}
		
		public boolean evaluateState() {
			return nextCheck < currentTimeMillis();
		}
		
		public void nextCheck() {
			nextCheck = currentTimeMillis() + SECONDS.toSeconds(60);
		}
	}
	
	@Inject
	@AccessKeys
	private DatabaseService db;

	@Inject
	@AccessKeys
	private Repository keys;
	
	@Inject
	private AccessKeyConfig config;
	
	private ConcurrentMap<AccessKeyId,AccessKeyState> states;
	
	@PostConstruct
	protected void initStateCheckCache() {
		this.states = new ConcurrentHashMap<>();
	}
	
	protected AccessKeyState getKeyState(AccessKeyId keyId) {
		AccessKeyState state = states.get(keyId);
		if(state == null) {
			AccessKeyState newState = new AccessKeyState();
			state = states.putIfAbsent(keyId, newState);
			if(state == null) {
				return newState;
			}
		}
		return state;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isRevoked(Jwt jwt) {
		
		Claims claims = jwt.getClaims();
		return isRevoked(claims);
	}

	public boolean isRevoked(Claims claims) {
		
		if ("true".equals(claims.getClaim("temporary"))) {
			// Temporary access keys cannot be revoked. 
			// They are short-living and get revoked by expiration automatically.
			return claims.isExpired();
		}
		
		// Check whether the long-living (i.e. non-temporary) access key still exists.
		AccessKeyId keyId = accessKeyId(claims.getJwtId());
		AccessKey key = keys.execute(findByAccessKeyId(keyId));
		
		// Non-temporary access keys must exist in the AUTH.ACCESSKEY table.
		// Otherwise, the access key has been revoked and is invalid.
		AccessKeyState state = getKeyState(key.getAccessKeyId());
		
		if(state.isRevoked()) {
			// Key is known to be revoked.
			return true;
		}

		// The access key state is evaluated every 60 seconds. 
		// The idea of this cache is to reduce the database queries.
		if(state.evaluateState()) {
			if(db.getSingleResult(prepare("SELECT uuid FROM auth.accesskey WHERE uuid = ?",
					  			  		  keyId),
					  			  rs -> rs.getString(1)) == null){
				// Key is revoked as no database record exists.
				state.revoked();
				LOG.warning(() -> format("Access attempt with revoked key %s (%s).", 
									 	 key.getAccessKeyName(), 
									 	 keyId));
				return true;
			}
			// Set next check timestamp.
			// Concurrent nextCheck updates are not a problem,
			// because intention is merely to reduce the database load but
			// not to have exactly one DB request per minute.
			state.nextCheck();
		}
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isValid(String token) {
		try {
			Claims claims = config.decodeAccessKey(token);
			if (claims.isExpired()) {
				return false;
			}
			return !isRevoked(claims);
			
		} catch (JwtException e) {
			LOG.log(Level.FINE,e.getMessage(),e);
			return false;
		}
	}
	
}