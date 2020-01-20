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
package io.leitstand.security.login.log.model;

import java.io.Serializable;

import io.leitstand.commons.model.ValueObject;

/**
 * User login record primary key.
 */
public class UserLoginRecordPK extends ValueObject implements Serializable{

	private static final long serialVersionUID = 1L;

	private Long id;
	private String localIp;
	
	/**
	 * JPA constructor.
	 */
	public UserLoginRecordPK() {
		// Default constructor
	}
	
	/**
	 * Creates a <code>UserLoginRecordPK</code>
	 * @param id the sequence number 
	 * @param localIp the IP address of the service, that has created the log record
	 */
	public UserLoginRecordPK(Long id, String localIp) {
		this.id = id;
		this.localIp = localIp;
	}
	
	/**
	 * Returns the log record sequence number.
	 * @return the log record sequence number.
	 */
	public Long getId() {
		return id;
	}
	
	/**
	 * Returns the IP address of the service, that has created the log record.
	 * @return the IP address of the service, that has created the log record.
	 */
	public String getLocalIp() {
		return localIp;
	}
	
}
