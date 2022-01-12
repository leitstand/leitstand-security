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
package io.leitstand.security.accesskeys.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import java.util.Date;

import javax.json.bind.annotation.JsonbProperty;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.accesskeys.AccessKeyId;

/**
 * The <code>AccessKeyInfo</code> value object conveys the ID, name, description and creation date of an access key.
 */
public class AccessKeyInfo extends ValueObject {

	/**
	 * Creates a new builder for an <code>AccessKeyInfo</code> object.
	 * @return a new builder for an <code>AccessKeyInfo</code> object.
	 */
	public static Builder newAccessKeyMetaData() {
		return new Builder();
	}
	
	/**
	 * Builder for an immutable <code>AccessKeyInfo</code> object or other objecs of classes derived from <code>AccessKeyInfo</code>.
	 */
	@SuppressWarnings("unchecked")
	public static class BaseAccessKeyInfoBuilder<T extends AccessKeyInfo,
								        		 B extends BaseAccessKeyInfoBuilder<T,B>>{
		protected T instance;
		
		protected BaseAccessKeyInfoBuilder(T instance) {
			this.instance = instance;
		}
	
		/**
		 * Sets the access key ID
		 * @param accessKeyId the access key ID
		 * @return a reference to this builder to continue with object creation
		 */
		public B withAccessKeyId(AccessKeyId accessKeyId) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyInfo)instance).accessKeyId = accessKeyId;
			return (B) this;
		}

		/**
		 * Sets the access key name
		 * @param accessKeyName the access key name
		 * @return a reference to this builder to continue with object creation
		 */
		public B withAccessKeyName(AccessKeyName accessKeyName) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyInfo)instance).accessKeyName = accessKeyName;
			return (B) this;
		}
		
		/**
		 * Sets the access key description
		 * @param description the access key description
		 * @return a reference to this builder to continue with object creation
		 */
		public B withDescription(String description) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyInfo)instance).description = description;
			return (B) this;
		}

		/**
		 * Sets the access key creation date
		 * @param dateCreated the access key creation date
		 * @return a reference to this builder to continue with object creation
		 */
		public B withDateCreated(Date dateCreated) {
			assertNotInvalidated(getClass(), instance);
			((AccessKeyInfo)instance).dateCreated = new Date(dateCreated.getTime());
			return (B) this;
		}
		
		/**
		 * Returns an immutable <code>AccessKeyInfo</code> (or sub-class) object and invalidates this builder.
		 * Subsequent calls to the <code>build()</code> method raise an exception. 
		 * @return the immutable <code>AccessKeyInfo</code> (or sub-class) object.
		 */
		public T build() {
			try {
				assertNotInvalidated(getClass(), instance);
				return instance;
			} finally {
				this.instance = null;
			}
		}	
	}
	
	/**
	 * Builder for an immutable <code>AccessKeyInfo</code> object.
	 */
	public static class Builder extends BaseAccessKeyInfoBuilder<AccessKeyInfo, Builder>{
		public Builder() {
			super( new AccessKeyInfo());
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
	
	/**
	 * Returns the access key ID.
	 * @return the access key ID.
	 */
	public AccessKeyId getAccessKeyId() {
		return accessKeyId;
	}
	
	/**
	 * Returns the access key name.
	 * @return the access key name.
	 */
	public AccessKeyName getAccessKeyName() {
		return accessKeyName;
	}
	
	/**
	 * Returns the access key description.
	 * @return the access key description.
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * Returns the access key creation date.
	 * @return the access key creation date.
	 */
	public Date getDateCreated() {
		return dateCreated;
	}
	
}
