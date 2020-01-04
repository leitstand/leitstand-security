/*
 *  (c) RtBrick, Inc - All rights reserved, 2015 - 2017
 */

import {Resource} from '/ui/js/client.js';

//TODO JSDoc

export class Records extends Resource{
	constructor(cfg) {
		super();
		this._cfg = cfg;
	}
		
	load(params) {
		return this.json("/api/v1/login/records?user_id={{&user_id}}&from={{&from}}&to={{&to}}&remote_ip={{&remote_ip}}&limit={{&limit}}",
						 this._cfg,
						 params)
				   .GET();
	}	
}

export class Record extends Resource {
	
	constructor(cfg) {
		super();
		this._cfg = cfg;
	}
	
	load(params) {
		return this.json("/api/v1/login/records/{{&local_ip}}/{{&id}}",
				  	     this._cfg,
				  	     params)
				   .GET();
	}

}