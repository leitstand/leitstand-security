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
