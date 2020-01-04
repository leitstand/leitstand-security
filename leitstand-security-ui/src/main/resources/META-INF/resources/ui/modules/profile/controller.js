/*
 *  (c) RtBrick, Inc - All rights reserved, 2015 - 2017
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
			let roles = new Roles();
			let allRoles = await roles.load();
			// Filter assigned roles
			let assignedRoles = allRoles.filter(role => profile.roles.includes(role.name));
			return {"profile":profile,
					"assigned_roles":assignedRoles};
		},
		buttons:{
			"save-settings":function(){
				// Update user profile. All changes have already been applied to the view model through the auto-bind feature.
				profile.saveSettings(this.location().params(),
									 this.getViewModel("profile"));
			},
			"passwd":function(){
				profile.passwd(this.location().params(),
							   {"uuid":this.getViewModel("uuid"),
								"password":this.input("password").value(),
							    "new_password":this.input("new_password").value(),
							    "confirmed_password":this.input("confirmed_password").value()});
			}
		}
	});
}
	
export const menu = new Menu({"me.html" : myController()},
							 "/ui/views/profile/me.html");