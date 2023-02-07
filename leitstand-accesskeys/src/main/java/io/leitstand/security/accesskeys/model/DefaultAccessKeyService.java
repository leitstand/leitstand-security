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

import static io.leitstand.commons.UniqueKeyConstraintViolationException.key;
import static io.leitstand.commons.db.DatabaseService.prepare;
import static io.leitstand.commons.model.StringUtil.isEmptyString;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.newAccessKeyEvent;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.Type.CREATED;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.Type.REVOKED;
import static io.leitstand.security.accesskeys.model.AccessKey.findByAccessKeyId;
import static io.leitstand.security.accesskeys.model.AccessKey.findByAccessKeyName;
import static io.leitstand.security.accesskeys.service.AccessKeyInfo.newAccessKeyMetaData;
import static io.leitstand.security.accesskeys.service.AccessKeySettings.newAccessKeySettings;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0001E_ACCESS_KEY_NOT_FOUND;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0005E_DUPLICATE_KEY_NAME;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskeys.ApiAccessKey.newApiAccessKey;

import java.util.List;

import javax.enterprise.event.Event;
import javax.inject.Inject;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UniqueKeyConstraintViolationException;
import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.accesskeys.event.AccessKeyEvent;
import io.leitstand.security.accesskeys.service.AccessKeyInfo;
import io.leitstand.security.accesskeys.service.AccessKeyName;
import io.leitstand.security.accesskeys.service.AccessKeyService;
import io.leitstand.security.accesskeys.service.AccessKeySettings;
import io.leitstand.security.auth.accesskeys.AccessKeyId;
import io.leitstand.security.auth.accesskeys.ApiAccessKey;
import io.leitstand.security.auth.accesskeys.ApiAccessKeyEncoder;

/**
 * The <code>DefaultAccessKeyService</code> allows managing the metadata of issued permanent API access keys.
 */
@Service
public class DefaultAccessKeyService implements AccessKeyService{

	private Repository repository;
	
	private DatabaseService db;
	
	private ApiAccessKeyEncoder encoder;
	
	private Event<AccessKeyEvent> events;
	
	protected DefaultAccessKeyService() {
		// CDI constructor
	}
	
	@Inject
	protected DefaultAccessKeyService(@AccessKeys Repository repository,
									  @AccessKeys DatabaseService db,
									  ApiAccessKeyEncoder encoder,
									  Event<AccessKeyEvent> events) {
			this.repository = repository;
			this.db = db;
			this.encoder = encoder;
			this.events = events;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public AccessKeySettings getAccessKey(AccessKeyId accessKeyId) {
		AccessKey key = loadAccessKey(accessKeyId);
		
		return newAccessKeySettings()
			   .withAccessKeyId(key.getAccessKeyId())
			   .withAccessKeyName(key.getAccessKeyName())
			   .withDescription(key.getDescription())
			   .withDateCreated(key.getDateCreated())
			   .withScopes(key.getScopes())
			   .build();
	
	}

	private AccessKey loadAccessKey(AccessKeyId accessKeyId) {
		AccessKey key = repository.execute(findByAccessKeyId(accessKeyId));
		if(key == null) {
			throw new EntityNotFoundException(AKY0001E_ACCESS_KEY_NOT_FOUND,
											  accessKeyId);
		}
		return key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String createAccessKey(AccessKeySettings accessKey) {
		AccessKeyId accessKeyId = accessKey.getAccessKeyId();
		AccessKey key = repository.execute(findByAccessKeyName(accessKey.getAccessKeyName()));
		if(key != null) {
			throw new UniqueKeyConstraintViolationException(AKY0005E_DUPLICATE_KEY_NAME,
															key("key_name",accessKey.getAccessKeyName()));
		}
		
		key = new AccessKey(accessKeyId,accessKey.getAccessKeyName());
		key.setDescription(accessKey.getDescription());
		key.setScopes(accessKey.getScopes());
		key.setDateCreated(accessKey.getDateCreated());
		repository.add(key);
		
		ApiAccessKey token = newApiAccessKey()
							 .withId(key.getAccessKeyId())
							 .withUserName(userName(key.getAccessKeyName().getValue()))
							 .withDateCreated(key.getDateCreated())
							 .withScopes(key.getScopes())
							 .build();
		
		events.fire(newAccessKeyEvent()
					.withAccessKeyId(key.getAccessKeyId())
					.withAccessKeyName(key.getAccessKeyName())
					.withAccessKeyStatus(CREATED)
					.build());
		
		return encoder.encode(token);
		
		
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void updateAccessKey(AccessKeyId accessKeyId, String description) {
		AccessKey key = loadAccessKey(accessKeyId);
		key.setDescription(description);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeAccessKey(AccessKeyId accessKeyId) {
		AccessKey key = repository.execute(findByAccessKeyId(accessKeyId));
		if(key != null) {
			repository.remove(key);
			events.fire(newAccessKeyEvent()
						.withAccessKeyId(accessKeyId)
						.withAccessKeyName(key.getAccessKeyName())
						.withAccessKeyStatus(REVOKED)
						.build());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<AccessKeyInfo> findAccessKeys(String filter) {
		String pattern = filter;
		if(isEmptyString(pattern)) {
			pattern = ".*";
		}
		
		return db.executeQuery(prepare("SELECT uuid, name, description, tscreated "+ 
									   "FROM auth.accesskey "+
									   "WHERE name ~ ? "+
									   "ORDER BY name", 
									   filter), 
							   rs -> newAccessKeyMetaData()
							   		 .withAccessKeyId(AccessKeyId.accessKeyId(rs.getString(1)))
							   		 .withAccessKeyName(AccessKeyName.accessKeyName(rs.getString(2)))
							   		 .withDescription(rs.getString(3))
							   		 .withDateCreated(rs.getTimestamp(4))
							   		 .build());
	}

}
