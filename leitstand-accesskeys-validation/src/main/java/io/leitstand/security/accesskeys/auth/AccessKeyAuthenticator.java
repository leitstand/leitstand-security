/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.auth;

import static io.leitstand.commons.db.DatabaseService.prepare;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.model.Service;
import io.leitstand.security.auth.accesskey.AccessKeyId;
import io.leitstand.security.auth.accesskey.ApiAccessKey;

/**
 * The <code>AccessKeyAuthenticator</code> verifies whether a valid {@link ApiAccessKey} has not been revoked 
 * and is allowed to execute the attempted operation.
 * <p>
 * An API access key is invalid if one of the following conditions is satisfied:
 * <ol>
 * 	<li>the API access key signature is invalid, i.e. the signature of the token does not match with the signature computed on the server</li>
 *  <li>the API access key has been revoked and must not be used any longer</li>
 * </ol>
 * A <em>valid</em> API access key is allowed to execute an operation all of the following conditions are satisfied:
 * <ol>
 * 	<li>The access key is granted to execute the specified HTTP method</li>
 *  <li>The access key is granted to access the resource path</li>
 * </ol>
 * The <code>AccessKeyValidator</code> runs a cache of valid access keys.
 * The <code>AccessKeyValidator</code> subscribes for {@link AccessKeyEvent} to update the cache instantly if a new 
 * key was added or a key has been revoked. Moreover, it refreshes the cache periodically (every 5 minutes) to add an 
 * additional level of robustness.
 */
@Service
public class AccessKeyAuthenticator {
	
	private static final Logger LOG = Logger.getLogger(AccessKeyAuthenticator.class.getName());

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
	
	private ConcurrentMap<AccessKeyId,AccessKeyState> states;
	
	@PostConstruct
	protected void initStateCheckCache() {
		this.states = new ConcurrentHashMap<>();
	}
	
	/**
	 * Checks whether an API access key is allowed to execute the given request.
	 * @param request - the request
	 * @param key - the valid access key to authenticate the request
	 * @return <code>true</code> if the API access key is authenticated to execute the request, <code>false</code> if not.
	 */
	public boolean isAllowed(HttpServletRequest request,
						   	 ApiAccessKey key) {
		if(isRevoked(key)) {
			return false;
		}
		return key.isMethodAllowed(request.getMethod()) && 
			   key.isPathAllowed(request.getRequestURI());
	}
	
	private boolean isRevoked(ApiAccessKey key) {
		if(key.isTemporary() ){
			if(key.isOlderThan(60, SECONDS)) {
				LOG.info(() -> format("Access attempt with an expired key %s (%s).", 
									  	key.getUserName(), 
									  	key.getId()));
				return true;
			}
			// If a temporary access key is not expired, the key is valid.
			return false;
		}
		
		// Non-temporary access keys must exist in the AUTH.ACCESSKEY table.
		// Otherwise, the access key has been revoked and is invalid.
		AccessKeyState state = getKeyState(key.getId());
		
		if(state.isRevoked()) {
			// Key is known to be revoked.
			return true;
		}

		// The access key state is evaluated every 60 seconds. 
		// The idea of this cache is to reduce the database queries.
		if(state.evaluateState()) {
			if(db.getSingleResult(prepare("SELECT uuid FROM auth.accesskey WHERE uuid = ?",
					  			  		  key.getId()),
					  			  rs -> rs.getString(1)) == null){
				// Key is revoked as no database record exists.
				state.revoked();
				LOG.warning(() -> format("Access attempt with revoked key %s (%s).", 
									 	 key.getUserName(), 
									 	 key.getId()));
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
	
	
	

	
}
