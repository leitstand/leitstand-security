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

import static javax.persistence.TemporalType.TIMESTAMP;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;

@Table(schema="auth", name="oauth2_refreshtoken")
@Entity
public class RefreshTokenStoreEntry implements Serializable{
	
	private static final long serialVersionUID = 1L;

	@Id
	private String sub;
	@Column(name="token64")
	private String refreshToken;
	
	@Temporal(TIMESTAMP)
	@Column(name="exp")
	private Date expiryDate;
	
	protected RefreshTokenStoreEntry() {
		// JPA
	}
	
	protected RefreshTokenStoreEntry(String sub, String refreshToken, Date dateExpiry) {
		this.sub = sub;
		this.refreshToken = refreshToken;
		this.expiryDate = dateExpiry;
	}
	
	public String getRefreshToken() {
		return refreshToken;
	}
	
	public String getSub() {
		return sub;
	}
	
	public boolean isExpired() {
		return new Date().after(expiryDate);
	}
	
}
