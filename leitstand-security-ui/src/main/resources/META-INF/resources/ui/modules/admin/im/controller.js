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
import {Roles,Role,Users,User} from './im.js';
import '../admin-components.js';

const rolesController = function() {
	const roles = new Roles();
	return new Controller({
		resource:roles,
		viewModel:function(roles){
			return {'roles':roles};
		}
	});
};

const roleController = function(){
	const role = new Role();
	return new Controller({
		resource:role,
		buttons:{
			'save-settings':function(){
				const settings = this.getViewModel();
				role.saveSettings(this.location.params,
								  this.settings)
			},
			'remove':function(){
				role.removeRole(this.location.params);
			}
		}
	})
}

const usersController = function() {
	const users = new Users();
	return new Controller({
		resource:users,
		viewModel:function(users){
			return {'users':users,
					'filter':this.location.param('filter')};
		},
		buttons:{
			'filter':function(){
				this.reload({'filter':this.getViewModel('filter')});
			}
		}
	});
};

const userController = function() {
	const user = new User();
	return new Controller({
		resource:user,
		viewModel:async function(userSettings){
			// Normalize TTL default
			if(userSettings.access_token_ttl === 0){
				userSettings.access_token_ttl = null;
			}
			
			const viewModel = {};
			viewModel.user=userSettings;
			
			// Add TTL units as transient array, i.e. it shall not be serialized with the view model
			viewModel.ttl_units=[{'value':'MINUTES','label':'Minutes'},
								 {'value':'HOURS','label':'Hours'},
								 {'value':'DAYS','label':'Days'}];			
			
			// Load all roles
			let roles = await new Roles().load();
			// ... and add them as transient properties, i.e. roles shall not be serialized with the view model
			viewModel.roles = roles;

			
			return viewModel;
		},
		buttons:{
			'save-settings':function(){
				user.store(this.location.params,
						   this.getViewModel("user"));
			},
			'passwd':function(){
				user.resetPassword(this.location.params,
								   {'new_password':this.input('new_password').value(),
								   	'confirmed_password':this.input('confirm_password').value()});
			},
			'remove':function(){
				user.remove(this.location.params);
			}
		},
		onRemoved : function(){
			this.navigate('users.html');
		}
	});
};

const addUserController = function() {
	const users = new Users();
	return new Controller({
		resource:users,
		viewModel: async function(){
			const viewModel = {};
			const roles = new Roles();
			viewModel.roles = await roles.load();
			return viewModel;
		},
		buttons:{
			'add-user':function(){
				users.add(this.getViewModel('user'));
			}
		},
		onCreated : function(location){
			this.navigate('users.html');
		}
	});
};

const addRoleController = function() {
	const roles = new Roles();
	return new Controller({
		resource:roles,
		viewModel:function(){
			return {};
		},
		buttons:{
			'add-role':function(){
				roles.addRole(this.getViewModel('role'));
			}
		},
		onCreated : function(location){
			this.navigate('roles.html');
		}
	});
};


const usersMenu = {
	'master' : usersController(),
	'details': { 'user.html' : userController(),
				 'passwd.html' : userController(),
				 'confirm-remove-user.html' : userController(),
				 'add-user.html':addUserController()}
};

const rolesMenu = {
	'master' : rolesController(),
	'details': {'role.html':roleController(),
				'confirm-remove-role.html':roleController(),
				'add-role.html':addRoleController()}
}

export const menu = new Menu({'users.html':usersMenu,
							  'roles.html':rolesMenu});
	
