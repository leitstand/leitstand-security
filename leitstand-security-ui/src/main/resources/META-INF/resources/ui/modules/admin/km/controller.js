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
import {Accesskeys,Accesskey} from './km.js';
import '../admin-components.js';

const accesskeysController = function() {
	const keys = new Accesskeys();
	return new Controller({
		resource:keys,
		viewModel:function(keys){
			return {'keys':keys,
					'filter':this.location.param('filter')};
		},
		buttons:{
			'filter':function(){
				this.reload({'filter':this.input('filter').value()});
			}
		}
	});
};

const accesskeyController = function(){
	const key = new Accesskey();
	return new Controller({
		resource:key,
		buttons:{
			'revoke':function(){
				key.revoke(this.location.params);
			},
			'save':function(){
				key.setDescription(this.location.params,
								   this.input('description').value());
			}
		},
		onSuccess:function(){
			this.navigate('/ui/views/admin/km/accesskeys.html');
		}
	});
};

const validatorController = function() {
	const key = new Accesskey();
	return new Controller({
		resource: key,
		buttons:{
			'validate':function(){
				key.validate(this.input('accesskey').value());
			}
		},
		onError:function(){
			this.renderView({'encoded':this.input('accesskey').value()});
		},
		onSuccess:function(accesskey){
			this.renderView({'accesskey':accesskey,
						     'encoded':this.input('accesskey').value()});
		}
	});
}

const newAccesskeyController = function() {
	const keys = new Accesskeys();
	return new Controller({
		resource:keys,
		viewModel:function(){
			return {};
		},
		buttons:{
			'create-accesskey':function(){
				keys.addAccesskey(this.getViewModel());
			}
		},
		onCreated:function(location,token){
			this.updateViewModel({'token':token});
			this.renderView();
		},
		onConflict:function(message){
			message.property='key_name';
			this.onInputError(message);
		}
	});
};

const accesskeysMenu = {
	'master' : accesskeysController(),
	'details': { 'new-accesskey.html' : newAccesskeyController(),
				 'confirm-revoke.html' : accesskeyController(),
				 'accesskey.html' : accesskeyController()}
};

export const menu = new Menu({'accesskeys.html':accesskeysMenu,
							  'validator.html':validatorController()});
