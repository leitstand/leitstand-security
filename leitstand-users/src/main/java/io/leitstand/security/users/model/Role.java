/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import io.leitstand.commons.model.AbstractEntity;
import io.leitstand.commons.model.Query;

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
@NamedQuery(name="Role.findAll",
			query="SELECT r FROM Role r ORDER BY r.name ASC")})
public class Role extends AbstractEntity implements Comparable<Role>{

	private static final long serialVersionUID = 1L;

	/**
	 * Returns a query to fetch a single role.
	 * @param role - the role name
	 * @return a query to fetch a single role.
	 */
	public static Query<Role> findRoleByName(String role) {
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

	private String name;
	private String description;
	
	/**
	 * JPA constructor.
	 */
	protected Role() {
		// JPA constructor
	}

	/**
	 * Create a <code>Role</code>.
	 * @param name - the role name
	 */
	Role(Long id, String name) {
		super(id);
		this.name = name;
	}
	
	/**
	 * Create a <code>Role</code>.
	 * @param name - the role name
	 */
	public Role(String name) {
		this.name = name;
	}
	
	/**
	 * Sets the role name.
	 * @param name - the role name
	 */
	public void setName(String name) {
		this.name = name;
	}
	
	/**
	 * Returns the role name.
	 * @return the role name.
	 */
	public String getName() {
		return name;
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
	 * @param description - the role description
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
		return getName().compareTo(o.getName());
	}
	
}