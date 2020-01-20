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
import {Resource} from '/ui/js/client.js';

/**
 * A user account reference.
 * @property {string} uuid the user account UUID
 * @typedef UserProfileReference
 */

/**
 * A password change request.
 * @typedef PasswordChangeRequest
 * @property {string} uuid the user account UUID
 * @property {string} password the current password to authorize the password change
 * @property {string} new_password the new password
 * @property {string} confirmed_password the confirmed password
 */

/**
 * The settings of a user profile.
 * @typedef UserProfileSettings
 * @property {string} uuid the user account UUID
 * @property {string} user_id the user login ID
 * @property {string} [given_name] the user's first name
 * @property {string} [sur_name] the user's last name
 * @property {string} [email] the user's email address
 */

/**
 * Resource to access a user profile.
 */	
export class UserProfile extends Resource{
	
		
	/**
	 * Loads the user profile.
	 * @param {UserProfileReference} ref the user profile reference.
	 */
	load(ref){
		return this.json("/api/v1/users/me",ref)
				   .GET();
	}
		
	/**
	 * Stores the user profile.
	 * @param {UserProfileReference} ref the user profile ID.
	 * @param {UserProfileSettings} settings the user profile settings.
	 */
	saveSettings(ref,settings){
		return this.json("/api/v1/users/{{&uuid}}",ref)
				   .PUT(settings);
	}
		
	/**
	 * Updates the user's password.
	 * @param {object} [ref.uuid] the user profile ID.
	 * @param {PasswordChangeRequest} passwd the change password request
	 */
	passwd(ref,passwd){
		return this.json("/api/v1/users/{{&uuid}}/_passwd",ref)
					.POST(passwd);
	}

}
