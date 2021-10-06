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
package io.leitstand.security.auth.accesskey;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static java.lang.System.currentTimeMillis;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.jsonb.DateToLongAdapter;
import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserName;

/**
 * An access key to for system-to-system authentication.
 */
public class ApiAccessKey extends ValueObject {
	
    /**
     * Creates an API access key builder.
     * @return the API access key builder.
     */
	public static Builder newApiAccessKey() {
		return new Builder();
	}
	
	/**
	 * Creates an API access key builder using the given access key as a template.
	 * @param template the template for the access key produced by the builder
	 * @return a builder to create a new access key
	 */
	public static Builder newApiAccessKey(ApiAccessKey template) {
		Builder builder = new Builder();
		builder.key.userName = template.getUserName();
		return builder;
	}
	
	/**
	 * A builder for API access keys.
	 */
	public static class Builder {
		
		private ApiAccessKey key = new ApiAccessKey();
		
		/**
		 * Sets the access key identifier.
		 * @param accessKeyId the access key identifier
		 * @return a reference to this builder to continue with object creation.
		 */
		public Builder withId(AccessKeyId accessKeyId) {
			assertNotInvalidated(getClass(), key);
			key.id = accessKeyId;
			return this;
		}
		
		/**
		 * Sets the user name the access key is created for.
		 * @param userName the user name
		 * @return a reference to this builder to continue with object creation.
		 */
		public Builder withUserName(UserName userName) {
			assertNotInvalidated(getClass(),  key);
			key.userName = userName;
			return this;
		}
		
		/**
		 * Sets the scopes assigned to this access key.
		 * @param scopes the access key scopes.
         * @return a reference to this builder to continue with object creation.
		 */
		public Builder withScopes(String... scopes) {
			return withScopes(asSet(scopes));
		}
		

		/**
         * Sets the scopes assigned to this access key.
         * @param scopes the access key scopes.
         * @return a reference to this builder to continue with object creation.
         */
		public Builder withScopes(Set<String> scopes) {
			assertNotInvalidated(getClass(),key);
			key.scopes = new TreeSet<>(scopes);
			return this;
		}
		
		/**
		 * Sets the creation date of the access key.
		 * @param dateCreated the creation date
         * @return a reference to this builder to continue with object creation.
		 */
		public Builder withDateCreated(Date dateCreated) {
			assertNotInvalidated(getClass(), key);
			key.dateCreated = new Date(dateCreated.getTime());
			return this;
		}

        /**
         * Sets the expiry date of the access key.
         * @param dateExpiry the creation date
         * @return a reference to this builder to continue with object creation.
         */
        public Builder withDateExpiry(Date dateExpiry) {
            assertNotInvalidated(getClass(), key);
            key.dateExpiry = new Date(dateExpiry.getTime());
            return this;
        }
        
        /**
         * Marks this access key as temporary access key.
         * Temporary access keys are not registered in the access key table and expire after 60s (by default).
         * @param temporary whether this access key is a temporary access key
         * @return a reference to this builder to continue with object creation
         */
        public Builder withTemporaryAccess(boolean temporary) {
            assertNotInvalidated(getClass(), key);
            key.temporary = temporary;
            if (temporary) {
                key.dateCreated = new Date(currentTimeMillis()+SECONDS.toMillis(60));
            }
            return this;
        }

        
		/**
		 * Creates the <code>ApiAccessKey</code> and invalidates this builder.
		 * Subsequent calls of the build method raise an exception.
		 * @return the <code>ApiAccessKey</code>
		 */
		public ApiAccessKey build() {
			try {
				assertNotInvalidated(getClass(), key);
				if(key.dateCreated == null) {
					key.dateCreated = new Date();
				}
				return key;
			} finally {
				this.key = null;
			}
		}

		
	}
	
		   
	private AccessKeyId id = randomAccessKeyId();
	
	private UserName userName;
	
	@JsonbTypeAdapter(DateToLongAdapter.class)
	private Date dateCreated;
	
	private Set<String> scopes = emptySet();
	
	private Date dateExpiry;
	private boolean temporary;
	
	
	public AccessKeyId getId() {
		return id;
	}
	
	public UserName getUserName() {
		return userName;
	}
	
	public Date getDateCreated() {
		return new Date(dateCreated.getTime());
	}
	
	public Date getDateExpiry() {
	    if (dateExpiry == null) {
	        return null;
	    }
	    return new Date(dateExpiry.getTime());
	}
	
	public boolean isExpired() {
		if (dateExpiry == null) {
		    return false;
		}
		return dateExpiry.after(new Date());
	}
	
	public Set<String> getScopes() {
		return unmodifiableSet(scopes);
	}

    public boolean isTemporary() {
        return temporary;
    }


}
