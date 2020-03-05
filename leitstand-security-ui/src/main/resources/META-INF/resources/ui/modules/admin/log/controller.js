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
import {Records,Record} from './log.js';

let recordsController = function() {
	let records = new Records();
	return new Controller({
		resource:records,
		viewModel:function(records){
			let viewModel = {};
			viewModel.records = records;
			viewModel.query = this.location.params;
			viewModel.default_from_date = viewModel.query.from ? new Date(viewModel.query.from) : new Date();
			viewModel.default_to_date = viewModel.query.to ? new Date(viewModel.query.to) : viewModel.default_from_date;
			viewModel.from = !!this.location.param('from');
			viewModel.to = !!this.location.param('to');
			return viewModel;
		},
		buttons:{
			'filter':function(){ 
				let query = this.getViewModel('query');
				if(!this.input('from').isChecked()){
					query.from=null;
				}
				if(!this.input('to').isChecked()){
					query.to=null;
				}				
				this.reload(query);
			}
		}
	});
}

let recordController = function() {
	let record = new Record();
	return new Controller({
		resource:record,
	});
}
	
let recordsMenu = {
	'master' : recordsController(),
	'details': { 'record.html' : recordController() }
}

export const menu = new Menu({'records.html':recordsMenu});
	
