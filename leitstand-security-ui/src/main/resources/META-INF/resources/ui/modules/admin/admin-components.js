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
import {Select,UIElement,html} from '/ui/js/ui-components.js';
import {Resource} from '/ui/js/client.js';


class Scopes extends Resource {

	load() {
		return this.json("/api/v1/_/scopes")
				   .GET();
	}

}

class ResourceScopes extends Select {
	
	constructor(){
		super();
	}
	
	get multiple(){
		return true;
	}
	
	options(){
		const scopes = new Scopes();
		return scopes.load()
					 .then( scopes => scopes.map(scope =>  {return {'value':scope}}));
	}
}

customElements.define('resource-scopes',ResourceScopes);

class AccessKey extends UIElement {
	
	constructor(){
		super();
	}
	
	renderDom(){
		const segments = this.innerText.split('.');
		this.innerHTML=html 
					`<code style="font-weight:bold; background-color:white; display:block; width: 60em; margin:auto; word-wrap:break-word; word-break:normal; white-space: pre-wap; border: 1px solid #eee">
					 <span style="color:#7BB772">$${segments[0]}</span>.<span style="color:#CC4B74">$${segments[1]}</span>.<span style="color:#75B7CE">$${segments[2]}</span>
					 </code>`
		
	}
	
	
}
customElements.define('access-key', AccessKey);
