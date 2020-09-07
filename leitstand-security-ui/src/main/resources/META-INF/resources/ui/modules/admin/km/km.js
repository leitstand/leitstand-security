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

//TODO JSDoc
export class Accesskeys extends Resource {
	
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
	
	addAccesskey(settings){
		return this.json("/api/v1/accesskeys")
		    	   .POST(settings);
	}

}

export class Accesskey extends Resource {
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
	
	restore(key){
	    return this.json("/api/v1/accesskeys/_restore")
	               .contentType("text/plain")
	               .POST(key);
	}
}	
