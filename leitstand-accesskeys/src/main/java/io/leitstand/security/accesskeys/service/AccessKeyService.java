/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.service;

import java.util.List;

import io.leitstand.security.auth.accesskey.AccessKeyId;

public interface AccessKeyService {

	AccessKeyData getAccessKey(AccessKeyId accessKeyId);
	String createAccessKey(AccessKeyData accessKey);
	void updateAccessKey(AccessKeyId accessKeyId,
						 String description);
	void removeAccessKey(AccessKeyId accessKeyId);
	List<AccessKeyMetaData> findAccessKeys(String filter);
	
}
