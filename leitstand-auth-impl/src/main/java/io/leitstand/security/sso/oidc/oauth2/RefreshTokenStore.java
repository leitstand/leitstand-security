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
package io.leitstand.security.sso.oidc.oauth2;

import java.util.Date;

/**
 * The <code>RefreshTokenStore</code> stores OAuth refresh tokens to renew access tokens.
 */
public interface RefreshTokenStore {
	
	/**
	 * Stores a user's refresh token.
	 * @param sub the user subject
	 * @param refreshToken64 the Base64-encoded refresh token 
	 * @param dateExpiry the expiry date of the refresh token
	 */
	void storeRefreshToken(String sub, String refreshToken64, Date expiryDate);
	
	/**
	 * Returns the user's refresh token or <code>null</code> if no refresh token for the use exists.
	 * @param sub the user subject
	 * @return the user's refresh token or <code>null</code> if no refresh token exists.
	 */
	String getRefreshToken(String sub);
	
}
