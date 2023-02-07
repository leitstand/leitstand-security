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
package io.leitstand.security.users.model;

import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static io.leitstand.commons.model.ByteArrayUtil.encodeBase64String;
import static io.leitstand.security.users.service.UserId.randomUserId;
import static io.leitstand.security.users.service.UserId.userId;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;
import static javax.persistence.EnumType.STRING;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Enumerated;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.MapKey;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import io.leitstand.commons.model.AbstractEntity;
import io.leitstand.commons.model.Query;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jpa.UserNameConverter;
import io.leitstand.security.users.jpa.EmailAddressConverter;
import io.leitstand.security.users.service.EmailAddress;
import io.leitstand.security.users.service.RoleName;
import io.leitstand.security.users.service.UserId;

/**
 * A user account.
 * <p>
 * A user account can have zero, one or many assigned roles. 
 * A {@link Role} defines functions and obligations 
 * and hence allows a user to call certain API functions. 
 * </p>
 * Every user account has an immutable UUID.
 * This UUID can be used as an external reference. 
 * By that, all other user account attributes can be updated 
 * even the user ID to log in to the system.
 */
@Entity
@Table(schema="auth", name="userdata")
@NamedQueries({
	@NamedQuery(name = "User.findUserById",
			    query= "SELECT u FROM User u WHERE u.uuid=:uuid"),
	@NamedQuery(name = "User.findUserByName",
				query= "SELECT u FROM User u WHERE u.name=:name")
})
public class User extends AbstractEntity {

	private static final long serialVersionUID = 1L;

	/**
	 * Returns a query to search a user account by its UUID.
	 * @param userId the user accounts UUID
	 * @return the user account
	 */
	public static Query<User> findUserById(UserId userId){
		return em -> em.createNamedQuery("User.findUserById",User.class)
					   .setParameter("uuid",userId.toString())
					   .getSingleResult();
	}

	/**
	 * Returns a query to search a user account by its user ID,
	 * i.e. the ID to log in to the system.
	 * @param userName the user name
	 * @return
	 */
	public static Query<User> findUserByName(UserName userName){
		return em -> em.createNamedQuery("User.findUserByName",User.class)
					   .setParameter("name",userName)
					   .getSingleResult();
	}
	
	private String uuid;
	
	@Convert(converter=UserNameConverter.class)
	private UserName name;
	
	private String givenName;
	
	private String familyName;

	@Convert(converter=EmailAddressConverter.class)
	private EmailAddress email;
	
	private int iterations;
	
	private String salt64;
	
	private String pass64;
	
	private long tokenTtl;
	
	@Enumerated(STRING)
	private TimeUnit tokenTtlUnit;
	
	@ManyToMany
	@JoinTable(schema="auth",
			   name="userdata_userrole", 
			   joinColumns= @JoinColumn(name="userdata_id", referencedColumnName="id"),
			   inverseJoinColumns=@JoinColumn(name="userrole_id",referencedColumnName="id"))
	@MapKey(name="name")
	private Map<RoleName,Role> roles;
	
	/**
	 * JPA constructor
	 */
	protected User() {
		//JPA constructor
		this.roles = new TreeMap<>();
	}
	
	/**
	 * Creates a <code>User</code> and assigns a random user account UUID.
	 * @param userName the user name
	 */
	public User(UserName userName) {
		this(randomUserId(),userName);
	}
	
	/**
	 * Creates a <code>User</code>.
	 * @param userId the user account UUID.
	 * @param userName the user name.
	 */
	public User(UserId userId, UserName userName) {
		this();
		this.uuid = userId.toString();
		this.name = userName;
	}

	/**
	 * Returns the user account UUID.
	 * @return the user account UUID.
	 */
	public UserId getUserId() {
		return userId(uuid);
	}
	
	/**
	 * Returns the user ID to log in to the system.
	 * @return the user login ID
	 */
	public UserName getUserName() {
		return name;
	}
	
	/**
	 * Sets the user name to log in to the system.
	 * @param userName the user name
	 */
	public void setUserName(UserName userName) {
		this.name = userName;
	}
	
	/**
	 * Returns the user's given name.
	 * @return the user's given name if set, <code>null</code> otherwise.
	 */
	public String getGivenName() {
		return givenName;
	}
	
	/**
	 * Sets the user's given name.
	 * @param givenName the user's given name
	 */
	public void setGivenName(String givenName) {
		this.givenName = givenName;
	}
	
	/**
	 * Returns the user's family name.
	 * @return the user's family if set, <code>null</code> otherwise 
	 */
	public String getFamilyName() {
		return familyName;
	}
	
	/**
	 * Sets the user's family name.
	 * @param familyName the user's family name.
	 */
	public void setFamilyName(String familyName) {
		this.familyName = familyName;
	}
	
	/**
	 * Sets the user's email address.
	 * @param email the user's email address.
	 */
	public void setEmailAddress(EmailAddress email) {
		this.email = email;
	}
	
	/**
	 * Returns the user's email address.
	 * @return the user's email address if set, <code>null</code> otherwise
	 */
	public EmailAddress getEmailAddress() {
		return email;
	}
	
	/**
	 * Returns the number of iterations to compute the password hash.
	 * @return the number of iterations to compute the password hash.
	 * @see #getPasswordHash()
	 * @see #getSalt()
	 */
	public int getIterations() {
		return iterations;
	}
	
	/**
	 * Returns the password hash value.
	 * @return the password hash value.
	 */
	public byte[] getPasswordHash() {
		if (pass64 != null) {
			return decodeBase64String(pass64);
		}
		return null;
	}
	
	/**
	 * Returns the salt value to compute the password hash.
	 * @return the salt value to compute the password hash.
	 */
	public byte[] getSalt() {
		if (salt64 != null) {
			return decodeBase64String(salt64);
		}
		return null;
	}
	
	/**
	 * Returns the names of all associated roles.
	 * @return an unmodifiable set of the names of all associated roles.
	 */
	public Set<RoleName> getRoleNames(){
		return unmodifiableSet(roles.keySet());
	}
	
	/**
	 * Returns an unmodifiable set of associated roles.
	 * @return the user's roles
	 */
	public Set<Role> getRoles(){
		return unmodifiableSet(new TreeSet<>(roles.values()));
	}
	
	/**
	 * Returns all associated roles mapped to the specified target type.
	 * @param mapping a function to map an associated role to a target type.
	 * @return an unmodifiable set of role description in the specified data type
	 */
	public <T> Set<T> getRoles(Function<Role,T> mapping){
		return unmodifiableSet(getRoles()
							   .stream()
							   .map(t -> mapping.apply(t))
							   .collect(toSet()));
	}
	
	/**
	 * Sets the user accounts roles.
	 * @param roles the user's roles
	 */
	public void setRoles(Collection<Role> roles) {
		Set<Role> newRoles = new HashSet<>(roles);
		List<Role> revRoles = new LinkedList<>();
		for(Role role : this.roles.values()) {
			// Preserve existing roles
			if(newRoles.remove(role)) {
				continue;
			}
			// If not assigned anylonger, add to list of revoked roles
			revRoles.add(role);
		}
		
		// Remove all revoked roles
		for(Role revoked : revRoles) {
			this.roles.remove(revoked.getRoleName());
		}
		
		// Add all roles not yet been assigned to the user.
		for(Role newRole : newRoles) {
			this.roles.put(newRole.getRoleName(),newRole);
		}
	}

	/**
	 * Checks whether the user has the specified role.
	 * @param name the role to be checked
	 * @return <code>true</code> if the user has the given role, <code>false</code> otherwise.
	 */
	public boolean isUserInRole(RoleName name) {
		return roles.containsKey(name);
	}
	
	/**
	 * Checks whether this user is allowed to access the specified scope.
	 * @param scope the scope name
	 * @return <code>true</code> when the user is allowed to access the specified scope.
	 */
	public boolean canAccessScope(String scope) {
		for(Role role : roles.values()) {
			if(role.includesScope(scope)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Sets the computed password hash value.
	 * @param hash the computed password hash value
	 * @param salt the salt that has been used to compute the password hash
	 * @param iterations the number of iterations when the password hash was computed
	 */
	public void setPassword(byte[] hash, 
							byte[] salt, 
							int iterations) {
		this.pass64 = encodeBase64String(hash);
		this.salt64 = encodeBase64String(salt);
		this.iterations = iterations;
	}
	
	public boolean isCustomTokenTimeout() {
		return tokenTtlUnit != null && tokenTtl > 0;
	}
	
	public long getTokenTtl() {
		return tokenTtl;
	}
	
	public TimeUnit getTokenTtlUnit() {
		return tokenTtlUnit;
	}
	
	public void setAccessTokenTtl(long duration, TimeUnit unit) {
		this.tokenTtl = (int) duration;
		this.tokenTtlUnit = unit;
	}

	public Set<String> getScopes() {
		Set<String> scopes = new TreeSet<>();
		for(Role role : roles.values()) {
			scopes.addAll(role.getScopes());
		}
		return unmodifiableSet(scopes);
	}
	
	
}
