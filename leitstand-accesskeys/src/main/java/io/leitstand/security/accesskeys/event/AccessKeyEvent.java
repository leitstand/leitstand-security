/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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
import io.leitstand.security.auth.accesskey.AccessKeyId;

public class AccessKeyEvent extends CompositeValue{
	
	public enum Type {
		CREATED,
		REVOKED
	}

	public static Builder newAccessKeyEvent() {
		return new Builder();
	}
	
	public static class Builder {
		
		private AccessKeyEvent event = new AccessKeyEvent();
		
		public Builder withAccessKeyId(AccessKeyId accessKeyId) {
			assertNotInvalidated(getClass(), event);
			event.accessKeyId = accessKeyId;
			return this;
		}
		
		public Builder withAccessKeyName(AccessKeyName accessKeyName) {
			assertNotInvalidated(getClass(), event);
			event.accessKeyName = accessKeyName;
			return this;
		}
		
		public Builder withAccessKeyStatus(Type type) {
			assertNotInvalidated(getClass(), event);
			event.type = type;
			return this;
		}
		
		
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
	
	public AccessKeyId getAccessKeyId() {
		return accessKeyId;
	}
	
	public AccessKeyName getAccessKeyName() {
		return accessKeyName;
	}
	
	public boolean isRevoked() {
		return type == REVOKED;
	}
	
	public boolean isCreated() {
		return type == CREATED;
	}
	
	
}
