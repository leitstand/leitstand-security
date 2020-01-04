/*
 *  (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */

import {Resource} from '/ui/js/client.js';

//TODO JSDoc

	
export class AccessKeys extends Resource {
	
	constructor(cfg) {
		super();
		this._cfg = cfg;
	}
	
	load(params) {
		return this.json("/api/v1/accesskeys?filter={{&filter}}",
						 this._cfg,
						 params)
				   .GET();
	}
	
	addAccessKey(settings){
		return this.json("/api/v1/accesskeys")
		    	   .POST(settings);
	}

}

export class AccessKey extends Resource {
	constructor(cfg) {
		super();
		this._cfg = cfg;
	}
		
	load(params) {
		return this.json("/api/v1/accesskeys/{{&key}}",
						 this._cfg,
						 params)
				   .GET();
	}
		
	setDescription(params,description){
		return this.json("/api/v1/accesskeys/{{&key}}/description",
						 this._cfg,
						 params)
				   .contentType("text/plain")
				   .PUT(description);
	}
	
	revoke(params){
		return this.resource("/api/v1/accesskeys/{{&key}}",
					  		 this._cfg,
					  		 params)
				   .DELETE();
	}
	
	validate(key){
		return this.json("/api/v1/accesskeys/_validate")
				   .contentType("text/plain")
				   .POST(key);
	}
}	
