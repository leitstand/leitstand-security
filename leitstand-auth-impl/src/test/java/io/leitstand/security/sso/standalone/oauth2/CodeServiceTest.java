package io.leitstand.security.sso.standalone.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Before;
import org.junit.Test;

public class CodeServiceTest {
	
	private CodeService service;

	@Before
	public void initCodeService() {
		service = new CodeService();
		service.initPRNG();
	}
	
	@Test
	public void create_and_decode_code() {
		String code = service.createCode("client", "user");
		CodePayload payload = service.decodeCode(code);
		assertEquals("client", payload.getClientId());
		assertEquals("user", payload.getUserName());
	}
	
	@Test
	public void returns_null_when_code_is_invalid() {
		assertNull(service.decodeCode("foobar"));
	}
	
	@Test
	public void returns_null_when_code_is_empty() {
		assertNull(service.decodeCode(""));
	}
	
	@Test
	public void returns_null_when_code_is_null() {
		assertNull(service.decodeCode(null));
	}
	
	
}
