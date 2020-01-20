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

import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static javax.persistence.EnumType.STRING;
import static javax.persistence.LockModeType.PESSIMISTIC_WRITE;
import static javax.persistence.TemporalType.TIMESTAMP;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Enumerated;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.JoinColumns;
import javax.persistence.NamedQuery;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;

import io.leitstand.commons.model.Query;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jpa.UserNameConverter;
import io.leitstand.security.login.log.service.UserLoginState;

/**
 * A login audit user log record entity.
 */
@Entity
@IdClass(UserLoginRecordPK.class)
@Table(schema="auth", name="user_login_audit_log")
@NamedQuery(name="UserLoginRecord.findLastRecord",
		    query="SELECT r FROM UserLoginRecord r WHERE r.localIp=:localIp AND r.id=(SELECT MAX(r.id) FROM UserLoginRecord r WHERE r.localIp=:localIp) ")
public class UserLoginRecord {
	
	public static Query<UserLoginRecord> fetchLastRecord(String localIp){
		return em -> em.createNamedQuery("UserLoginRecord.findLastRecord",UserLoginRecord.class)
					   .setParameter("localIp",localIp)
					   .setLockMode(PESSIMISTIC_WRITE)
					   .getSingleResult();
		
	}
	

	@OneToOne
	@JoinColumns({
			@JoinColumn(name="previous_user_login_audit_log_id", referencedColumnName="id", nullable=true, updatable=false, insertable=false),
			@JoinColumn(name="localip",referencedColumnName="localip", updatable=false, insertable=false)
	})
	private UserLoginRecord	previousLogin;
	
	@Id
	private Long 	id;
	
	@Id
	@Column(name="localip")
	private String  localIp;

	@Column(name="remoteip")
	private String  remoteIp;
	
	@Convert(converter=UserNameConverter.class)
	@Column(name="username")
	private UserName 	userName;
	
	@Column(name="useragent")
	private String 	userAgent;
	
	@Column(name="loginstate")
	@Enumerated(STRING)
	private UserLoginState loginState;

	@Column(name="tslogin")
	@Temporal(TIMESTAMP)
	private Date 	loginDate;
	
	@Column(name="signature")
	private String 	signature;
	
	/**
	 * JPA constructor
	 */
	protected UserLoginRecord() {
		// JPA constructor
	}
	
	/**
	 * Creates a <code>UserLoginRecord</code>.
	 * @param id the log record sequence number
	 * @param previousLogin the previous log record to implement the log record chain
	 * @param localIp the local IP address of the service writing this record
	 * @param remoteIp the remote IP address of the client, that attempts to login
	 * @param userName the user ID of the user that attempts to login
	 * @param userAgent the user agent (HTTP header) used to login
	 * @param loginDate the login timestamp
	 * @param loginState the outcome of the login attempt
	 * @param signature the signature of the log record
	 */
	protected UserLoginRecord(Long id,
							  UserLoginRecord previousLogin, 
							  String localIp, 
							  String remoteIp, 
							  UserName userName, 
							  String userAgent,
							  Date loginDate,
							  UserLoginState loginState,
							  String signature) {
		this.previousLogin = previousLogin;
		this.id			   = id;
		this.localIp 	   = localIp;
		this.userName 	   = userName;
		this.remoteIp 	   = remoteIp;
		this.userAgent 	   = userAgent;
		this.loginDate	   = new Date(loginDate.getTime());
		this.loginState    = loginState;
		this.signature 	   = signature;
	}
	
	/**
	 * Returns the log record sequence number.
	 * @return the log record sequence number.
	 */
	public Long getId() {
		return id;
	}
	
	/**
	 * The user ID of the user that attempted to login
	 * @return the user ID
	 */
	public UserName getUserName() {
		return userName;
	}
	
	/**
	 * Returns the user agent used by the user, when he attempted to login.
	 * @return the user agent or <code>null</code> if no user agent was set.
	 */
	public String getUserAgent() {
		return userAgent;
	}
	
	/**
	 * Returns the IP address of the host from which a user attempted to login.
	 * @return the client IP address
	 */
	public String getRemoteIp() {
		return remoteIp;
	}
	
	/**
	 * Returns the IP address of the service that has written the login record.
	 * @return the IP address of the service that has written the login record.
	 */
	public String getLocalIp() {
		return localIp;
	}
	
	/**
	 * Returns the timestamp of the login attempt.
	 * @return the timestamp of the login attempt.
	 */
	public Date getLoginDate() {
		return new Date(loginDate.getTime());
	}
	
	/**
	 * Returns the signature as binary data.
	 * @return the signature as byte array.
	 */
	public byte[] getSignature() {
		return decodeBase64String(signature);
	}
	
	/**
	 * Returns the Base64 encoded signature.
	 * @return the Base64 encoded signature.
	 */
	public String getSignature64() {
		return signature;
	}
	
	/**
	 * Returns the login attempt result.
	 * @return the login attempt result.
	 */
	public UserLoginState getState() {
		return loginState;
	}

	/**
	 * Returns the previous log record of the log record chain.
	 * @return the previous log record or <code>null</code> if this record is the first chain record.
	 */
	public UserLoginRecord getPreviousLogRecord() {
		return previousLogin;
	}
	
}
