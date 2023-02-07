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
package io.leitstand.security.accesskeys.service;

import java.util.List;

import io.leitstand.commons.ConflictException;
import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.security.auth.accesskeys.AccessKeyId;

/**
 * The <code>AccessKeyService</code> provides the means to manage API access-key metadata.
 */
public interface AccessKeyService {

	/**
	 * Returns the access key with the given ID.
	 * @param accessKeyId the access key ID
	 * @return the access key settings
	 * @throws EntityNotFoundException if the access key does not exist
	 */
	AccessKeySettings getAccessKey(AccessKeyId accessKeyId);
	
	/**
	 * Creates a new access key.
	 * @param accessKey the access key settings
	 * @return the serialized access key as JSON Web Token.
	 * @throws ConflictException if an access key with the same name already exists
	 */
	String createAccessKey(AccessKeySettings accessKey);
	
	/**
	 * Updates the description of an access key.
	 * @param accessKeyId the access key ID
	 * @param description the access key description
	 * @throws EntityNotFoundException if the access key does not exist
	 */
	void updateAccessKey(AccessKeyId accessKeyId,
						 String description);
	
	/**
	 * Removes an access key. 
	 * Removing an access also invalidates the access token associated with the access key.
	 * @param accessKeyId the access key ID
	 */
	void removeAccessKey(AccessKeyId accessKeyId);
	
	/**
	 * Lists all access key with a matching name.
	 * @param filter the name pattern
	 * @return a list of matching access keys or an empty list if no matching access keys exist.
	 */
	List<AccessKeyInfo> findAccessKeys(String filter);
	
}
