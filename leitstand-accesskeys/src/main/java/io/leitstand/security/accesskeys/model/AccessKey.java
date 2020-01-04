/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.model;

import static java.util.Collections.unmodifiableSet;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import io.leitstand.commons.model.AbstractEntity;
import io.leitstand.commons.model.Query;
import io.leitstand.security.accesskeys.jpa.AccessKeyIdConverter;
import io.leitstand.security.accesskeys.jpa.AccessKeyNameConverter;
import io.leitstand.security.accesskeys.service.AccessKeyName;
import io.leitstand.security.auth.accesskey.AccessKeyId;

@Entity
@Table(schema="auth", name="accesskey")
@NamedQuery(name="AccessKey.findByAccessKeyId",
			query="SELECT k FROM AccessKey k WHERE k.uuid=:uuid")
@NamedQuery(name="AccessKey.findByAccessKeyName",
			query="SELECT k FROM AccessKey k WHERE k.name=:name")
@NamedQuery(name="AccessKey.findByNamePattern",
			query="SELECT k FROM AccessKey k WHERE CONCAT('',k.name) REGEXP :pattern ORDER BY k.name")
public class AccessKey extends AbstractEntity{

	private static final long serialVersionUID = 1L;

	public static Query<AccessKey> findByAccessKeyId(AccessKeyId accessKeyId){
		return em -> em.createNamedQuery("AccessKey.findByAccessKeyId",AccessKey.class)
					   .setParameter("uuid",accessKeyId)
					   .getSingleResult();
	}
	
	public static Query<AccessKey> findByAccessKeyName(AccessKeyName accessKeyName) {
		return em -> em.createNamedQuery("AccessKey.findByAccessKeyName",AccessKey.class)
				   	   .setParameter("name",accessKeyName)
				   	   .getSingleResult();
	}
	
	public static Query<List<AccessKey>> findByNamePattern(String pattern){
		return em -> em.createNamedQuery("AccessKey.findByNamePattern",AccessKey.class)
					   .setParameter("pattern",pattern)
					   .getResultList();
	}
	
	@Convert(converter=AccessKeyIdConverter.class)
	private AccessKeyId uuid;
	@Convert(converter=AccessKeyNameConverter.class)
	private AccessKeyName name;
	private String description;
	
	@ElementCollection
	@CollectionTable(schema="auth", 
					 name="accesskey_method", 
					 joinColumns=@JoinColumn(name="accesskey_id", referencedColumnName="id"))
	@Column(name="method")
	private Set<String> methods;

	@ElementCollection
	@CollectionTable(schema="auth", 
			 name="accesskey_path", 
			 joinColumns=@JoinColumn(name="accesskey_id", referencedColumnName="id"))
	@Column(name="path")
	private Set<String> paths;
	
	protected AccessKey() {
		// JPA constructor
	}
	
	public AccessKey(AccessKeyId accessKeyId,
					 AccessKeyName accessKeyName) {
		this.uuid = accessKeyId;
		this.name = accessKeyName;
		this.methods = new TreeSet<>();
		this.paths = new TreeSet<>();
	}
	

	public AccessKeyId getAccessKeyId() {
		return uuid;
	}
	
	public void addMethod(String method) {
		this.methods.add(method);
	}
	
	public void addPath(String path) {
		this.paths.add(path);
	}
	
	public Set<String> getPaths() {
		return unmodifiableSet(paths);
	}

	public Set<String> getMethods() {
		return unmodifiableSet(methods);
	}

	public AccessKeyName getAccessKeyName() {
		return name;
	}
	
	public void setDescription(String description) {
		this.description = description;
	}
	
	public String getDescription() {
		return description;
	}


	
}