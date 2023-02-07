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
package io.leitstand.security.accesskeys.event;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.Type.CREATED;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.Type.REVOKED;

import javax.json.bind.annotation.JsonbProperty;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.leitstand.commons.model.CompositeValue;
import io.leitstand.security.accesskeys.service.AccessKeyName;
import io.leitstand.security.auth.accesskeys.AccessKeyId;

/**
 * AccessKeyEvent reports when an access key got created or has been revoked.
 */
public class AccessKeyEvent extends CompositeValue{
	
	public enum Type {
		CREATED,
		REVOKED
	}

	/**
	 * Returns a builder for an immutable <code>AccessKeyEvent</code>.
	 * @return an <code>AccessKeyEvent</code> builder.
	 */
	public static Builder newAccessKeyEvent() {
		return new Builder();
	}
	
	public static class Builder {
		
		private AccessKeyEvent event = new AccessKeyEvent();
		
		/**
		 * Sets the access key ID.
		 * @param accessKeyId the access key ID
		 * @return a reference to this builder to continue with object creation
		 */
		public Builder withAccessKeyId(AccessKeyId accessKeyId) {
			assertNotInvalidated(getClass(), event);
			event.accessKeyId = accessKeyId;
			return this;
		}
		
		
		/**
		 * Sets the access key name.
		 * @param accessKeyName the access key name
		 * @return a reference to this builder to continue object creation
		 */
		public Builder withAccessKeyName(AccessKeyName accessKeyName) {
			assertNotInvalidated(getClass(), event);
			event.accessKeyName = accessKeyName;
			return this;
		}
		
		/**
		 * Sets the event type representing whether the key has been created or revoked.
		 * @param type the access key type
		 * @return a reference to this builder to continue object creation
		 */
		public Builder withAccessKeyStatus(Type type) {
			assertNotInvalidated(getClass(), event);
			event.type = type;
			return this;
		}
		
		
		/**
		 * Creates an immutable <code>AccessKeyEvent</code> and invalidates this builder.
		 * Subsequent calls of the <code>build()</code> method raise an exception.
		 * @return the immutable <code>AccessKeyEvent</code>.
		 */
		public AccessKeyEvent build() {
			try {
				assertNotInvalidated(getClass(), event);
				return event;
			} finally {
				this.event = null;
			}
		}
		
	}
	
	
	
	@JsonbProperty("key_id")
	@NotNull(message="{key_id.required}")
	@Valid
	private AccessKeyId accessKeyId;

	@NotNull(message="{key_name.required}")
	@Valid
	@JsonbProperty("key_name")
	private AccessKeyName accessKeyName;
	
	@NotNull
	private AccessKeyEvent.Type type;
	
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
	 * Returns whether the access key has been revoked.
	 * @return <code>true</code> if the access key is revoked, <code>false</code> if not.
	 */
	public boolean isRevoked() {
		return type == REVOKED;
	}
	
	/**
	 * Returns whether the access key has been created.
	 * @return <code>true</code> if this event refers to a new access key, <code>false</code> if not.
	 */
	public boolean isCreated() {
		return type == CREATED;
	}
	
	
}
