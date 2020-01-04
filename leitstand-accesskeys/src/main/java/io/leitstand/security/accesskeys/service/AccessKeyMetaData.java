/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import java.util.Date;

import javax.json.bind.annotation.JsonbProperty;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.leitstand.commons.model.CompositeValue;
import io.leitstand.security.auth.accesskey.AccessKeyId;

public class AccessKeyMetaData extends CompositeValue {
	
	public static Builder newAccessKeyMetaData() {
		return new Builder();
	}
	
	public static class MetaDataBuilder<T extends AccessKeyMetaData,
								        B extends MetaDataBuilder<T,B>>{
		protected T instance;
		
		public MetaDataBuilder(T instance) {
			this.instance = instance;
		}
	
		public B withAccessKeyId(AccessKeyId accessKeyId) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyMetaData)instance).accessKeyId = accessKeyId;
			return (B) this;
		}
		
		public B withAccessKeyName(AccessKeyName accessKeyName) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyMetaData)instance).accessKeyName = accessKeyName;
			return (B) this;
		}
		
		public B withDescription(String description) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyMetaData)instance).description = description;
			return (B) this;
		}

		public B withDateCreated(Date dateCreated) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyMetaData)instance).dateCreated = new Date(dateCreated.getTime());
			return (B) this;
		}
		
		public T build() {
			try {
				assertNotInvalidated(getClass(), instance);
				return instance;
			} finally {
				this.instance = null;
			}
		}	
	}
	
	public static class Builder extends MetaDataBuilder<AccessKeyMetaData, Builder>{
		public Builder() {
			super( new AccessKeyMetaData());
		}
	}
	
	@JsonbProperty("key_id")
	@Valid
	private AccessKeyId accessKeyId = AccessKeyId.randomAccessKeyId();
	
	@JsonbProperty("key_name")
	@Valid
	@NotNull(message="{key_name.required}")
	private AccessKeyName accessKeyName;
	private String description;
	private Date dateCreated;
	
	public AccessKeyId getAccessKeyId() {
		return accessKeyId;
	}
	
	public AccessKeyName getAccessKeyName() {
		return accessKeyName;
	}
	
	public String getDescription() {
		return description;
	}
	
	public Date getDateCreated() {
		return dateCreated;
	}
	
}
