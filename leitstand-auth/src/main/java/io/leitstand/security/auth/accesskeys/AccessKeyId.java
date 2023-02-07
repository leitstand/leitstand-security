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
package io.leitstand.security.auth.accesskeys;

import static java.util.UUID.randomUUID;

import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.jsonb.AccessKeyIdAdapter;

/**
 * Unique access key identifier.
 */
@JsonbTypeAdapter(AccessKeyIdAdapter.class)
public class AccessKeyId extends Scalar<String>{

	private static final long serialVersionUID = 1L;

    /**
     * Alias of {@link #valueOf(String)} to avoid static import conflicts.
     *
     * Creates an <code>AccessKeyId</code> from the given string.
     * @param id the access key identifier
     * @return the <code>AccessKeyId</code> or <code>null</code> if the given string is <code>null</code> or empty.
     */
	public static AccessKeyId accessKeyId(String id) {
		return valueOf(id);
	}
	
	/**
	 * Creates a random <code>AccessKeyId</code>.
	 * @return a random <code>AccessKeyId</code>.
	 */
	public static AccessKeyId randomAccessKeyId() {
		return valueOf(randomUUID().toString());
	}
	
	/**
	 * Creates an <code>AccessKeyId</code> from the given string.
	 * @param id the access key identifier
	 * @return the <code>AccessKeyId</code> or <code>null</code> if the given string is <code>null</code> or empty.
	 */
	public static AccessKeyId valueOf(String id) {
		return fromString(id,AccessKeyId::new);
	}

	private String value;
	
	/**
	 * Creates a <code>AccessKeyId</code> instance.
	 * @param value the access key identifier
	 */
	public AccessKeyId(String value) {
		this.value = value;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public  String getValue() {
		return value;
	}

	
}
