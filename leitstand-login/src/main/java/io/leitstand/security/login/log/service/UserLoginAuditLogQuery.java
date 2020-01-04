/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.login.log.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import java.util.Date;

import io.leitstand.commons.model.ValueObject;

/**
 * An immutable query for login audit log records.
 */
public class UserLoginAuditLogQuery extends ValueObject{
	
	/**
	 * Returns a builder to create a new login audit log query. 
	 * @return a builder to create a new login audit log query.
	 */
	public static Builder newUserLoginAuditLogQuery() {
		return new Builder();
	}
	
	/**
	 * The builder for a login audit log record query.
	 * The builder is invalidated after the query was built and must not be used
	 * after calling the {@link #build()} method.
	 */
	public static class Builder{
		private static final int DEFAULT_LIMIT = 100;
		private UserLoginAuditLogQuery query = new UserLoginAuditLogQuery();
		
		/**
		 * Sets the optional user ID pattern the record's user ID must match.
		 * @param userIdPattern
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withUserIdPattern(String userIdPattern) {
			assertNotInvalidated(getClass(), query);
			query.userIdPattern = userIdPattern;
			return this;
		}
		
		/**
		 * Sets the optional timestamp after which the log record must have been written to the
		 * login audit log.
		 * @param date - the timestamp value
		 * @return a reference to this builder to continue with object creation
		 * @see #withToLoginDate(Date)
		 */
		public Builder withFromLoginDate(Date date) {
			assertNotInvalidated(getClass(), query);
			query.fromLoginDate = date != null ? new Date(date.getTime()) : null;
			return this;
		}
		
		/**
		 * Sets the optional timestamp before which the log record must have been written to the
		 * login audit log.
		 * @param date - the timestamp value
		 * @return a reference to this builder to continue with object creation
		 * @see #withFromLoginDate(Date)
		 */
		public Builder withToLoginDate(Date date) {
			assertNotInvalidated(getClass(), query);
			query.toLoginDate = date != null ? new Date(date.getTime()) : null;
			return this;
		}
		
		/**
		 * Sets the optional remote IP address from which the login attempt must have been made.
		 * @param remoteIp - the remote IP address
		 * @return a reference to this builder to continue object creation
		 */
		public Builder withRemoteIp(String remoteIp) {
			assertNotInvalidated(getClass(), query);
			query.remoteIp = remoteIp;
			return this;
		}
		
		/**
		 * Sets the optional limit of records returned by this query.
		 * The default limit is {@value #DEFAULT_LIMIT} records.
		 * Zero and all negative values are silently ignored and result into the 
		 * default limit being applied
		 * @param limit - the positive maximum number of records returned by this query
		 * @return a reference to this builder to continue object creation
		 */
		public Builder withLimit(int limit) {
			assertNotInvalidated(getClass(), query);
			if(limit > 0) {
				query.limit = limit;
			}
			return this;
		}
		
		/**
		 * Builds the immutable login audit log query and invalidates this builder.
		 * Subsequent invocation of any of this builder methods causes an exception.
		 * @return the immutable login audit log query
		 */
		public UserLoginAuditLogQuery build() {
			try {
				assertNotInvalidated(getClass(), query);
				return query;
			} finally {
				this.query = null;
			}
		}
	}
	
	private Date fromLoginDate;
	private Date toLoginDate;
	private String userIdPattern;
	private String remoteIp;
	private int limit = Builder.DEFAULT_LIMIT;
	
	/**
	 * Returns the remote IP address from which the login attempt must have been made or
	 * <code>null</code> if no remote IP address was specified.
	 * @return the remote IP address from which the login attempt must have been made or
	 * <code>null</code> if no remote IP address was specified.
	 */
	public String getRemoteIp() {
		return remoteIp;
	}

	/**
	 * Returns the timestamp after which the log record must have been written to the audit log or
	 * <code>null</code> if no from timestamp was specified.
	 * @return the timestamp after which the log record must have been written to the audit log or
	 * <code>null</code> if no from timestamp was specified.
	 */
	public Date getFromLoginDate() {
		return fromLoginDate != null ? new Date(fromLoginDate.getTime()) : null;
	}
	
	/**
	 * Returns the timestamp before which the log record must have been written to the audit log or
	 * <code>null</code> if no before timestamp was specified.
	 * @return the timestamp before which the log record must have been written to the audit log or
	 * <code>null</code> if no before timestamp was specified.
	 */
	public Date getToLoginDate() {
		return toLoginDate != null ? new Date(toLoginDate.getTime()) : null;
	}
	
	/**
	 * Returns the user ID pattern the log record's user ID must match or
	 * <code>null</code> if no such pattern was specified.
	 * @return the user ID pattern the log record's user ID must match or
	 * <code>null</code> if no such pattern was specified.
	 */
	public String getUserIdPattern() {
		return userIdPattern;
	}
	
	/**
	 * Returns the maximum number of records returned by this query. 
	 * @return the maximum number of records returned by this query.
	 */
	public int getLimit() {
		return limit;
	}
	
}


