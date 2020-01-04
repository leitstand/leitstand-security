/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.tool;

import static java.lang.String.format;

import java.io.Console;
import java.util.Scanner;

class ConsoleDelegate {
	
	
	private Console console;
	
	ConsoleDelegate() {
		this.console = System.console();
	}
	
	void printf(String message, Object... args) {
		if(console != null) {
			console.printf(message, args);
		} else {
			System.out.println(format(message, args));
		}
	}
	
	String readLine(String prompt, Object... args) {
		if(console != null) {
			return console.readLine(prompt, args);
		}
		// Mitigate eclipse issue 122429122429
		try(Scanner scanner = new Scanner(System.in)){
			printf(prompt);
			return scanner.nextLine();
		}
	}

	char[] readPassword(String prompt, Object... args) {
		if(console != null) {
			return console.readPassword(prompt,args);
		}
		printf("Cannot obtain console.");
		printf("Password will be echoed to console!");
		// Mitigate eclipse issue 122429122429
		try(Scanner scanner = new Scanner(System.in)){
			printf(prompt);
			return scanner.nextLine().toCharArray();
		}

	}
	
}
