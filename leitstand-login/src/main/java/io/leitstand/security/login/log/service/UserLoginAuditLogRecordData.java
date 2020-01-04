/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.login.log.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import java.util.Date;

import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.jsonb.IsoDateAdapter;
import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserId;


/**
 * An immutable representation of a login audit log record.
 */
public class UserLoginAuditLogRecordData extends ValueObject {
	
	/**
	 * Returns a builder to create an immutable login audit log record.
	 * @return a builder to create an immutable login audit log record.
	 */
	public static Builder newUserLoginRecordData() {
		return new Builder();
	}			
	
	/**
	 * The builder to create an immutable login audit log record.
	 * The builder gets invalidated when calling the {@link #build()} and 
	 * must not be used after the <code>build()</code> method invocation anymore.
	 *
	 */
	public static class Builder {
		
		private UserLoginAuditLogRecordData instance = new UserLoginAuditLogRecordData();
		
		/**
		 * Sets the log record's sequence number.
		 * @param id - the sequence number
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withId(Long id) {
			assertNotInvalidated(getClass(), instance);
			instance.id = id;
			return this;
		}
		
		/**
		 * Sets the IP address of the authentication service that has verified the provided credentials.
		 * @param localIp - the authentication service IP address
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withLocalIp(String localIp) {
			assertNotInvalidated(getClass(), instance);
			instance.localIp = localIp;
			return this;
		}
		
		/**
		 * Sets the IP address from which the login attempt was made
		 * @param remoteIp - the client IP address
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withRemoteIp(String remoteIp) {
			assertNotInvalidated(getClass(), instance);
			instance.remoteIp = remoteIp;
			return this;
		}
		
		/**
		 * Sets the user ID of the authenticated user.
		 * @param userId - the user ID
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withUserId(UserId userId) {
			assertNotInvalidated(getClass(), instance);
			instance.userId = userId;
			return this;
		}
		
		/**
		 * Sets whether the provided credentials were valid and the user passed the login verification, 
		 * or the credentials were invalid and authentication failed.
		 * @param loginState - the authentication result
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withLoginState(UserLoginState loginState) {
			assertNotInvalidated(getClass(), instance);
			instance.loginState = loginState;
			return this;
		}
		
		/**
		 * Sets the user agent from which the login attempt was made.
		 * @param userAgent - the recorded <code>User-Agent</code> HTTP header
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withUserAgent(String userAgent) {
			assertNotInvalidated(getClass(), instance);
			instance.userAgent = userAgent;
			return this;
		}

		/**
		 * Sets whether the record signature is valid and the specified previous record exists. 
		 * @param valid - <code>true</code> if the record is valid, <code>false</code> otherwise.
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withValid(boolean valid) {
			assertNotInvalidated(getClass(), instance);
			instance.valid = valid;
			return this;
		}
		
		/**
		 * Sets the timestamp of the login.
		 * @param loginDate - the login timestamp
 		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withLoginDate(Date loginDate) {
			assertNotInvalidated(getClass(), instance);
			instance.loginDate = new Date(loginDate.getTime());
			return this;
		}
		
		/**
		 * Returns an immutable login record and invalidates this builder.
		 * Subsequent invocations of any method of this builder fail and raise an exception.
		 * Hence the builder must not be used after calling the <code>build()</code> method anymore.
		 * @return the immutable login record
		 */
		public UserLoginAuditLogRecordData build() {
			try {
				assertNotInvalidated(getClass(), instance);
				return instance;
			} finally {
				this.instance = null;
			}
		}
		
	}
	
	private Long id;
	private String localIp;
	private String remoteIp;
	private UserId userId;
	private UserLoginState loginState;
	@JsonbTypeAdapter(IsoDateAdapter.class)
	private Date loginDate;
	private boolean valid;
	private String userAgent;
	
	/**
	 * Returns the login audit log record sequence number.
	 * @return the login audit log record sequence number.
	 */
	public Long getId() {
		return id;
	}
	
	/**
	 * Returns the IP address of the authentication service that has created this loging audit log record.
	 * @return the IP address of the authentication service.
	 */
	public String getLocalIp() {
		return localIp;
	}
	
	/**
	 * Returns the client IP address.
	 * @return the client IP address.
	 */
	public String getRemoteIp() {
		return remoteIp;
	}
	
	/**
	 * Returns the user ID.
	 * @return the user ID.
	 */
	public UserId getUserId() {
		return userId;
	}
	
	/**
	 * Returns the outcome of the login attempt.
	 * @return the outcome or the login attempt.
	 */
	public UserLoginState getLoginState() {
		return loginState;
	}
	
	/**
	 * Returns the login timestamp.
	 * @return the login timestamp.
	 */
	public Date getLoginDate() {
		return new Date(loginDate.getTime());
	}
	
	/**
	 * Returns the <code>User-Agent</code> HTTP header recorded when the login request was processed.
	 * @return the user agent
	 */
	public String getUserAgent() {
		return userAgent;
	}
	
	/**
	 * Returns whether this login audit log record is valid.
	 * A record is valid, if the signature is valid and the referenced previous log record exists.
	 * @return <code>true</code> if the login record is valid, <code>false</code> otherwise.
	 */
	public boolean isValid() {
		return valid;
	}
	


}