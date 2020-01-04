/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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