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
package io.leitstand.security.users.tool;

import static io.leitstand.commons.etc.Environment.emptyEnvironment;
import static io.leitstand.commons.model.ByteArrayUtil.encodeBase36String;
import static io.leitstand.commons.model.ByteArrayUtil.encodeBase64String;

import io.leitstand.security.crypto.MasterSecret;

public class MasterSecretTool {
	
	public static void main(String[] args) {
		ConsoleDelegate console = new ConsoleDelegate();	
		MasterSecret masterSecret = new MasterSecret(emptyEnvironment());
		masterSecret.init();
		char[] secret = console.readPassword("Enter secret to be encrypted: ");
		byte[] cypher = masterSecret.encrypt(new String(secret));
		console.printf("Base36: %s",encodeBase36String(cypher));
		console.printf("Base64: %s",encodeBase64String(cypher));

		
	}

}
