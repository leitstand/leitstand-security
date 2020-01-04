/*
 *  (c) RtBrick, Inc - All rights reserved, 2015 - 2017
 */

import {Controller,Menu} from '/ui/js/ui.js';
import {AccessKeys,AccessKey} from './km.js';

let accessKeysController = function() {
	var keys = new AccessKeys();
	return new Controller({
		resource:keys,
		viewModel:function(keys){
			return {"keys":keys,
					"filter":this.location().param("filter")};
		},
		buttons:{
			"filter":function(){
				this.reload({"filter":this.input("filter").value()});
			}
		}
	});
};


let accessKeyController = function(){
	let key = new AccessKey();
	return new Controller({
		resource:key,
		buttons:{
			"revoke":function(){
				key.revoke(this.location().params());
			},
			"save":function(){
				key.setDescription(this.location().params(),
								   this.input("description").value());
			}
		},
		onSuccess:function(){
			this.navigate("/ui/views/admin/km/accesskeys.html");
		}
	});
};

let validatorController = function() {
	let key = new AccessKey();
	return new Controller({
		resource: key,
		buttons:{
			"validate":function(){
				key.validate(this.input("accesskey").value());
			}
		},
		onError:function(){
			this.render({"encoded":this.input("accesskey").value()});
		},
		onSuccess:function(accesskey){
			this.render({"accesskey":accesskey,
						 "encoded":this.input("accesskey").value()});
		}
	});
}



let newAccessKeyController = function() {
	let keys = new AccessKeys();
	return new Controller({
		resource:keys,
		buttons:{
			"create-accesskey":function(){
				var submission = { "key_name" : this.input("key_name").value(),	
						    	   "description" : this.input("description").value(),
						    	   "methods": this.input("method").values(), 
						    	   "paths": this.input("path").values() };
				
				keys.addAccessKey(submission);
			},
			"select-all-methods":function(){
				this.elements("input[name='method']").forEach(function(element){
					element.check(true);
				});
			},
			"deselect-all-methods":function(){
				this.elements("input[name='method']").forEach(function(element){
					element.check(false);
				});
			},
			"select-all-paths":function(){
				this.elements("input[name='path']").forEach(function(element){
					element.check(true);
				});
			},
			"deselect-all-paths":function(){
				this.elements("input[name='path']").forEach(function(element){
					element.check(false);
				});
			}
		},
		onCreated:function(location,token){
			this.render("token",{"location":location,
								 "token":token});
			this.element("create").css().add("hidden");
		},
		onConflict:function(message){
			message.property="key_name";
			this.onInputError(message);
		}
	});
};


let usersMenu = {
	"master" : accessKeysController(),
	"details": { "new-accesskey.html" : newAccessKeyController(),
				 "confirm-revoke.html" : accessKeyController(),
				 "accesskey.html" : accessKeyController()}
};

export const menu = new Menu({"accesskeys.html":usersMenu,
							  "validator.html":validatorController()});