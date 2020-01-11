/*
 *  (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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