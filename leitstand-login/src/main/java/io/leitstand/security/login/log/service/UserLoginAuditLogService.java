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
package io.leitstand.security.login.log.service;

import java.util.List;

import io.leitstand.security.auth.UserName;

/**
 * The <code>UserLoginAuditLogService</code> provides functions to log all login attempts, 
 * to query the login audit log and to read single login audit log records.
 * <p>
 * The login audit log is implemented as chain. 
 * Every record contains a reference to its previous record and 
 * is digitally signed to be able to detect modification to a record.
 * 
 */
public interface UserLoginAuditLogService {

	/**
	 * Creates a new login audit log record.
	 * @param remoteIp the IP address from which the user attempted to login
	 * @param userAgent the used client software (e.g. web browser) as expressed by the <code>User-Agent</code> HTTP header
	 * @param userName the user that attempted to login
	 * @param loginState the result of the login attempt
	 */
	void log(String remoteIp, 
			 String userAgent, 
			 UserName userName, 
			 UserLoginState loginState);
	
	/**
	 * Returns a login audit log record.
	 * @param localIp the IP address of the authentication service that processed the login request
	 * @param id the unique ID of the login record
	 * @return the login record data
	 * @throws EntityNotFoundException if the requested log record does not exist.
	 */
	UserLoginAuditLogRecordData getUserLoginRecord(String localIp, 
												   Long id);
	
	/**
	 * Executes a query for login audit log records. 
	 * @param query the login audit log query 
	 * @return a list of matching records or an empty list if not records were found
	 */
	List<UserLoginAuditLogRecordData> findUserLoginAuditLogRecords(UserLoginAuditLogQuery query);
	
}
