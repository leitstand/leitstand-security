/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.tool;

import static io.leitstand.commons.model.ByteArrayUtil.encodeBase36String;
import static io.leitstand.commons.model.ByteArrayUtil.encodeBase64String;
import static io.leitstand.security.users.model.PasswordService.ITERATIONS;

import io.leitstand.security.users.model.PasswordService;

public class PasswordTool {

	public static void main(String[] args) throws Exception {
		PasswordService service = new PasswordService();
		ConsoleDelegate console = new ConsoleDelegate();
		console.printf("Password tool to compute salt and hash value for a given password.");
		char[] passw = console.readPassword("Please enter a password: ");
		byte[] salt = service.salt();
		byte[] hash = service.hash(passw,salt,ITERATIONS);
		
		console.printf("Iter: %d", ITERATIONS);
		console.printf("Base64");
		console.printf("Salt: %s", encodeBase64String(salt));
		console.printf("Hash: %s", encodeBase64String(hash));
		console.printf("Base36");
		console.printf("Salt: %s", encodeBase36String(salt));
		console.printf("Hash: %s", encodeBase36String(hash));
		
	}
	
}