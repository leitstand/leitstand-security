/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

/**
 * The user settings of a Leitstand user.
 * <p>
 * Use <code>{@literal @Inject} {@literal @Authenticated} UserSettings</code> to obtain
 * the settings of the authenticated user 
 * or <code>{@literal @Inject} {@literal @Authenticated} UserId</code> to get the user ID
 * of the authenticated user.
 *  
 */
public class UserSettings extends UserReference{
	
	public static Builder newUserSettings() {
		return new Builder();
	}
	
	public static class UserSettingsBuilder<T extends UserSettings, B extends UserSettingsBuilder<T,B>> extends UserReferenceBuilder<UserSettings, B  >{
		
		public UserSettingsBuilder(T object) {
			super(object);
		}
		
		public B withDateCreated(Date date) {
			assertNotInvalidated(getClass(), instance);
			instance.dateCreated = new Date(date.getTime());
			return (B) this;
		}
		
		public B withDateModified(Date date) {
			assertNotInvalidated(getClass(), instance);
			instance.dateModified = new Date(date.getTime());
			return (B) this;
		}
		
		public B withRoles(String... roles) {
			return withRoles(asSet(roles));
		}
		
		public B withAccessTokenTtl(long duration, TimeUnit unit) {
			assertNotInvalidated(getClass(), instance);
			instance.accessTokenTtl = duration;
			instance.accessTokenTtlUnit = unit;
			return (B) this;
		}

		public B withRoles(Set<String> roles) {
			assertNotInvalidated(getClass(), instance);
			instance.roles = new TreeSet<>(roles);
			return (B) this;
		}

	}
	
	public static class Builder extends UserSettingsBuilder<UserSettings,Builder> {
		public Builder() {
			super(new UserSettings());
		}

	}
	
	private Date   dateCreated;
	private Date   dateModified;
	private Long   accessTokenTtl;
	private TimeUnit accessTokenTtlUnit;
	private Set<String> roles = emptySet();
	
	public Date getDateCreated() {
		if(dateCreated != null) {
			return new Date(dateCreated.getTime());
		}
		return null;
	}
	
	public Date getDateModified() {
		if(dateModified != null) {
			return new Date(dateModified.getTime());
		}
		return null;
	}
	
	public Set<String> getRoles(){
		return unmodifiableSet(roles);
	}

	public Long getAccessTokenTtl() {
		return accessTokenTtl;
	}
	
	public TimeUnit getAccessTokenTtlUnit() {
		return accessTokenTtlUnit;
	}
	
	public boolean isCustomAccessTokenTtl() {
		return accessTokenTtl != null && accessTokenTtlUnit != null;
	}
}
