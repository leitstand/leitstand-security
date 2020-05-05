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
//TODO Add JSDoc
export class Users extends Resource {
	
	constructor(cfg){
		super();
		this._cfg = cfg;
	}
	
	load(params) {
		return this.json("/api/v1/users?filter={{&filter}}",
						 this._cfg,
						 params)
				   .GET();
	}
	

	add(user){
		return this.json("/api/v1/users")
		    	   .POST(user);
	}
}

export class Roles extends Resource {

	load() {
		return this.json("/api/v1/userroles")
				   .GET();
	}

	addRole(params){
		return this.json("/api/v1/userroles")
				   .POST(params);
	}
	
}

export class Role extends Resource {

	load(params) {
		return this.json("/api/v1/userroles/{{role}}",params)
				   .GET();
	}

	store(params,settings){
		return this.json("/api/v1/userroles/{{role}}",params)
				   .PUT(settings);
	}
	
	removeRole(params){
		return this.json("/api/v1/userroles/{{role}}",params)
		   		   .DELETE(params);		
	}
	
}

export class User extends Resource {
	
	constructor(cfg){
		super();
		this._cfg = cfg;
	}
	
	load(params) {
		return this.json("/api/v1/users/{{&user}}",
						 this._cfg,
						 params)
				   .GET();
	}
		
	store(params, settings){
		return this.json("/api/v1/users/{{&user}}",
				  		 this._cfg,
				  		 params)
				   .PUT(settings);
	}
	
	resetPassword(params,settings){
		return this.json("/api/v1/users/{{&user}}/_reset",
				  		 this._cfg,
				  		 params)
				   .POST(settings);
	}
		
	remove(params){
		return this.json("/api/v1/users/{{&user}}",
				  		 this._cfg,
				  		 params)
				   .DELETE();
	}

}	
