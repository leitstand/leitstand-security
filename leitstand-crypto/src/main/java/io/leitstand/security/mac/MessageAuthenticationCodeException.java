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
package io.leitstand.security.mac;


/**
 * The <code>MessageAuthenticationCodeException</code> is thrown whenever a problem occurred while computing a message authentication code.
 */
public class MessageAuthenticationCodeException extends RuntimeException {
 	
	private static final long serialVersionUID = 1L;

	/**
	 * Create a <code>MessageAuthenticationCodeException</code>.
	 * @param cause - the root cause
	 */
	public MessageAuthenticationCodeException(Exception cause) {
		super(cause);
	}
}
