/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static java.util.Collections.emptySet;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import io.leitstand.security.auth.accesskey.ApiAccessKey;

@RunWith(Parameterized.class)
public class ApiAccessKeyMethodTest {
	
	@Parameters
	public static Collection<Object[]> methodAccessTable(){
									 					
	return Arrays.asList(new Object[][] {//  GET    PUT    POST   DELETE	
		{emptySet(),	 	  		 		 true,  true,  true,  true },
		{asSet("DELETE"),		   			 false, false, false, true },
		{asSet("POST"),						 false, false, true,  false },
		{asSet("POST","DELETE"),		   	 false, false, true,  true },
		{asSet("PUT"),						 false, true,  false, false },
		{asSet("PUT","DELETE"),	 		   	 false, true,  false, true },
		{asSet("PUT","POST"),		   		 false, true,  true,	 false },
		{asSet("PUT","POST","DELETE"),		 false, true,  true,  true},
		{asSet("GET"),		   				 true,  false, false, false},
		{asSet("GET","DELETE"),		   		 true,  false, false, true},
		{asSet("GET","POST"),		  	 	 true,  false, true,  false},
		{asSet("GET","POST","DELETE"),		 true,  false, true,  true},
		{asSet("GET","PUT"),		  		 true,  true,  false, false},
		{asSet("GET","PUT","DELETE"),		 true,  true,  false, true},
		{asSet("GET","PUT","POST"),		     true,  true,   true, false},
		{asSet("GET","PUT","POST","DELETE"), true,  true,   true, true}});
	}
	
	
	private ApiAccessKey key;
	private boolean getAllowed;
	private boolean putAllowed;
	private boolean postAllowed;
	private boolean deleteAllowed;
	
	public ApiAccessKeyMethodTest(Set<String> methods,
								  boolean getAllowed,
								  boolean putAllowed,
								  boolean postAllowed,
								  boolean deleteAllowed) {
		
		key = newApiAccessKey()
			  .withMethods(methods)
			  .build();
		this.getAllowed = getAllowed;
		this.putAllowed = putAllowed;
		this.postAllowed = postAllowed;
		this.deleteAllowed = deleteAllowed;
	}
	
	@Test
	public void method_access_is_granted_as_defined() {
		assertThat(getAllowed, is(key.getPayload().isMethodAllowed("GET")));
		assertThat(putAllowed, is(key.getPayload().isMethodAllowed("PUT")));
		assertThat(postAllowed, is(key.getPayload().isMethodAllowed("POST")));
		assertThat(deleteAllowed, is(key.getPayload().isMethodAllowed("DELETE")));

	}
	
}
