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
import {Controller,Menu} from '/ui/js/ui.js';
import {Roles} from '/ui/modules/admin/im/im.js';
import {UserProfile} from './profile.js';

function myController(){
	let profile = new UserProfile();
	return new Controller({
		resource:profile,
		viewModel: async function(profile){
			// Load all existing roles
			const roles = new Roles();
			const allRoles = await roles.load();
			// Filter assigned roles
			const assignedRoles = allRoles.filter(role => profile.roles.includes(role.role_name));
			return {"profile":profile,
					"assigned_roles":assignedRoles};
		},
		postRender: function(){
			const profile = this.getViewModel("profile");
			if (profile.oidc_only){
				this.elements("ui-input").forEach((input) => input.setAttribute("readonly"));
			}	
		},
		buttons:{
			"save-settings":function(){
				// Update user profile. All changes have already been applied to the view model through the auto-bind feature.
				profile.saveSettings(this.location.params,
									 this.getViewModel("profile"));
			},
			"passwd":function(){
				profile.passwd(this.location.params,
							   {"uuid":this.getViewModel("user_id"),
								"password":this.input("password").value(),
							    "new_password":this.input("new_password").value(),
							    "confirmed_password":this.input("confirmed_password").value()});
			}
		}
	});
}
	
export const menu = new Menu({"me.html" : myController()},
							 "/ui/views/profile/me.html");
