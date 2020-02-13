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

import static io.leitstand.security.users.service.RoleId.roleId;
import static java.util.Collections.unmodifiableSet;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import io.leitstand.commons.jpa.BooleanConverter;
import io.leitstand.commons.model.Query;
import io.leitstand.commons.model.VersionableEntity;
import io.leitstand.security.users.jpa.RoleNameConverter;
import io.leitstand.security.users.service.RoleId;
import io.leitstand.security.users.service.RoleName;

/**
 * A role expresses functions and obligations in an organization.
 * <p>
 * The EMS defines certain roles and defines which roles are allowed to call what functions.
 * </p>
 * <p>
 * Users and roles form a many-to-many relationship.
 * A user can have multiple roles and 
 * a role is typically assigned to multiple users.
 * Thus all roles are stored in the identity management database 
 * to be able to assign user to their roles.
 * </p>
 */
@Entity
@Table(schema="auth", name="userrole")
@NamedQueries({
@NamedQuery(name="Role.findByName", 
	 		query="SELECT r FROM Role r WHERE r.name=:name"),
@NamedQuery(name="Role.findById", 
			query="SELECT r FROM Role r WHERE r.uuid=:uuid"),
@NamedQuery(name="Role.findAll",
			query="SELECT r FROM Role r ORDER BY r.name ASC")})
public class Role extends VersionableEntity implements Comparable<Role>{

	private static final long serialVersionUID = 1L;

	
	/**
	 * Returns a query to fetch a role by its ID.
	 * @param role the role name
	 * @return a query to fetch a single role.
	 */
	public static Query<Role> findRoleById(RoleId role){
		return em -> em.createNamedQuery("Role.findById",Role.class)
					   .setParameter("uuid", role.toString())
					   .getSingleResult();
	}
	
	/**
	 * Returns a query to fetch a role by its name.
	 * @param role the role name
	 * @return a query to fetch a single role.
	 */
	public static Query<Role> findRoleByName(RoleName role) {
		return em -> em.createNamedQuery("Role.findByName",Role.class)
					   .setParameter("name",role)
					   .getSingleResult();
	}
	
	/**
	 * Returns a query to fetch all existing roles.
	 * @return a query to fetch all existing roles.
	 */
	public static Query<List<Role>> findAllRoles(){
		return em -> em.createNamedQuery("Role.findAll", Role.class)
					   .getResultList();
	}

	@Convert(converter = RoleNameConverter.class)
	@Column(unique=true)
	private RoleName name;
	private String description;
	@ElementCollection
	@CollectionTable(schema="auth", 
					 name="userrole_scope", 
					 joinColumns=@JoinColumn(name="userrole_id", referencedColumnName="id"))
	@Column(name="scope")
	private Set<String> scopes;
	@Convert(converter=BooleanConverter.class)
	private boolean system;
	
	/**
	 * JPA constructor.
	 */
	protected Role() {
		// JPA constructor
	}

	/**
	 * Create a <code>Role</code>.
	 * @param roleId the role ID
	 * @param roleName the role name
	 */
	protected Role(RoleId roleId, RoleName roleName) {
		super(roleId.toString());
		this.name = roleName;
	}
		
	public RoleId getRoleId() {
		return roleId(getUuid());
	}
	
	/**
	 * Sets the role name.
	 * @param name the role name
	 */
	public void setRoleName(RoleName name) {
		this.name = name;
	}
	
	/**
	 * Returns the role name.
	 * @return the role name.
	 */
	public RoleName getRoleName() {
		return this.name;
	}
	
	/**
	 * Returns the role description.
	 * @return the role description.
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * Sets the role description.
	 * @param description the role description
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Implements a natural ordering by role name.
	 * <p>
	 * {@inheritDoc}
	 */
	@Override
	public int compareTo(Role o) {
		return getRoleName().compareTo(o.getRoleName());
	}
	
	/**
	 * Returns the scopes this role can access.
	 * @return the scopes this role can access.
	 */
	public Set<String> getScopes() {
		return unmodifiableSet(scopes);
	}
	
	/**
	 * Sets the scopes this role can access.
	 * @param scopes
	 */
	public void setScopes(Set<String> scopes) {
		this.scopes = new HashSet<>(scopes);
	}

	/**
	 * Returns <code>true</code> if users in this role can access the specified scope.
	 * @param scope the scope 
	 * @return <code>true</code> if users in this role can accss the specified scope.
	 */
	public boolean includesScope(String scope) {
		return scopes.contains(scope);
	}
	
	/**
	 * Returns whether this role is a system role. 
	 * System roles cannot be removed
	 * @return <code>true</code> if this role is a system role that cannot be removed.
	 */
	public boolean isSystemRole() {
		return system;
	}

	void setSystemRole(boolean b) {
		this.system = true;
	}
	
}
