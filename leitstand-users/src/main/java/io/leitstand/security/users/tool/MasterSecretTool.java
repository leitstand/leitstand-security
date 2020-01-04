/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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
