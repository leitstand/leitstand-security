/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.login.log.service;

/**
 * Enumeration of user login states.
 */
public enum UserLoginState {
	/** User passed login attempt.*/
	PASSED,
	
	/** User's login attempt failed.*/
	FAILED	
}