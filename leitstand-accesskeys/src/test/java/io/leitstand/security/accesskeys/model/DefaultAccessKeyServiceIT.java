/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.accesskeys.service.AccessKeyData.newAccessKey;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0001E_ACCESS_KEY_NOT_FOUND;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0005E_DUPLICATE_KEY_NAME;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Date;

import javax.enterprise.event.Event;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UniqueKeyConstraintViolationException;
import io.leitstand.commons.model.Repository;
import io.leitstand.security.accesskeys.auth.AccessKeyEncodingService;
import io.leitstand.security.accesskeys.event.AccessKeyEvent;
import io.leitstand.security.accesskeys.service.AccessKeyData;
import io.leitstand.security.accesskeys.service.AccessKeyName;
import io.leitstand.security.accesskeys.service.ReasonCode;
import io.leitstand.security.auth.accesskey.AccessKeyId;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.jwt.JsonWebTokenConfig;
import io.leitstand.security.crypto.Secret;

public class DefaultAccessKeyServiceIT extends AccessKeysIT{

	private Repository repository;
	private DefaultAccessKeyService service;
	private ArgumentCaptor<AccessKeyEvent> captor;
	private AccessKeyEncodingService encoder;
	
	@Before
	public void initResources() {
		repository = new Repository(getEntityManager());
		JsonWebTokenConfig config = mock(JsonWebTokenConfig.class);
		when(config.getSecret()).thenReturn(new Secret(toUtf8Bytes("unittest")));
		Event event = mock(Event.class);
		captor = ArgumentCaptor.forClass(AccessKeyEvent.class);
		doNothing().when(event).fire(captor.capture());
		encoder = new AccessKeyEncodingService(config);
		service = new DefaultAccessKeyService(repository,
											  encoder,
											  event);
	}
	
	@Test
	public void fire_EntityNotFoundException_if_access_key_does_not_exist() {
		try {
			service.getAccessKey(randomAccessKeyId());
			fail("Exception expected!");
		} catch(EntityNotFoundException e){
			assertEquals(ReasonCode.AKY0001E_ACCESS_KEY_NOT_FOUND,e.getReason());
		}
	}
	
	@Test
	public void can_create_new_access_key_without_methods_and_path_restriction() {
		
		AccessKeyData key = newAccessKey()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(AccessKeyName.valueOf("general"))
							.withDateCreated(new Date())
							.withDescription("Unittest access key")
							.build();
		String token = service.createAccessKey(key);
		assertNotNull(token);
		
		ApiAccessKey decoded = encoder.decode(token);
		assertEquals(key.getAccessKeyId(),decoded.getId());
		assertEquals(key.getAccessKeyName().toString(),decoded.getUserName().toString());
		assertTrue(decoded.isMethodAllowed("foo")); // No restrictions on methods at all
		assertTrue(decoded.isPathAllowed("/foo/bar"));
		
		AccessKeyEvent event = captor.getValue();
		assertTrue(event.isCreated());
		assertEquals(key.getAccessKeyId(),event.getAccessKeyId());
		assertEquals(key.getAccessKeyName(),event.getAccessKeyName());
		
	}
	
	@Test
	public void can_create_new_access_key_with_method_restriction() {
		
		AccessKeyData key = newAccessKey()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(AccessKeyName.valueOf("method"))
							.withDateCreated(new Date())
							.withMethods("put","post","get")
							.withDescription("Unittest access key")
							.build();
		String token = service.createAccessKey(key);
		assertNotNull(token);
		
		ApiAccessKey decoded = encoder.decode(token);
		assertEquals(key.getAccessKeyId(),decoded.getId());
		assertEquals(key.getAccessKeyName().toString(),decoded.getUserName().toString());
		assertTrue(decoded.isMethodAllowed("post"));
		assertTrue(decoded.isMethodAllowed("get"));
		assertTrue(decoded.isMethodAllowed("put"));
		assertFalse(decoded.isMethodAllowed("delete"));
		
		AccessKeyEvent event = captor.getValue();
		assertTrue(event.isCreated());
		assertEquals(key.getAccessKeyId(),event.getAccessKeyId());
		assertEquals(key.getAccessKeyName(),event.getAccessKeyName());

		
	}
	
	@Test
	public void can_create_new_access_key_with_path_restriction() {
		
		AccessKeyData key = newAccessKey()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(AccessKeyName.valueOf("path"))
							.withDateCreated(new Date())
							.withPaths("/foo")
							.withDescription("Unittest access key")
							.build();
		String token = service.createAccessKey(key);
		assertNotNull(token);
		
		ApiAccessKey decoded = encoder.decode(token);
		assertEquals(key.getAccessKeyId(),decoded.getId());
		assertEquals(key.getAccessKeyName().toString(),decoded.getUserName().toString());
		assertTrue(decoded.isPathAllowed("/foo"));
		assertFalse(decoded.isPathAllowed("/bar"));
		
		AccessKeyEvent event = captor.getValue();
		assertTrue(event.isCreated());
		assertEquals(key.getAccessKeyId(),event.getAccessKeyId());
		assertEquals(key.getAccessKeyName(),event.getAccessKeyName());

		
	}
	
	
	@Test
	public void can_create_new_access_key_with_method_and_path_restriction() {
		
		AccessKeyData key = newAccessKey()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(AccessKeyName.valueOf("method_path"))
							.withDateCreated(new Date())
							.withMethods("put","post","get")
							.withPaths("/foo","/bar")
							.withDescription("Unittest access key")
							.build();
		String token = service.createAccessKey(key);
		assertNotNull(token);
		
		ApiAccessKey decoded = encoder.decode(token);
		assertEquals(key.getAccessKeyId(),decoded.getId());
		assertEquals(key.getAccessKeyName().toString(),decoded.getUserName().toString());
		assertTrue(decoded.isMethodAllowed("post"));
		assertTrue(decoded.isMethodAllowed("get"));
		assertTrue(decoded.isMethodAllowed("put"));
		assertFalse(decoded.isMethodAllowed("delete"));
		assertTrue(decoded.isPathAllowed("/foo"));
		assertTrue(decoded.isPathAllowed("/bar"));
		assertFalse(decoded.isPathAllowed("/test"));
		
		AccessKeyEvent event = captor.getValue();
		assertTrue(event.isCreated());
		assertEquals(key.getAccessKeyId(),event.getAccessKeyId());
		assertEquals(key.getAccessKeyName(),event.getAccessKeyName());

		
	}
	
	@Test
	public void cannot_create_keys_with_same_name() {
		
		AccessKeyData key = newAccessKey()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(AccessKeyName.valueOf("unique_test"))
							.withDateCreated(new Date())
							.withMethods("put","post","get")
							.withPaths("/foo","/bar")
							.withDescription("Unittest access key")
							.build();
		transaction(() -> {
			String token = service.createAccessKey(key);
			assertNotNull(token);
		});
		
		transaction(() -> {
			try {
				service.createAccessKey(key);
				fail("Exception expected");
			} catch (UniqueKeyConstraintViolationException e) {
				assertEquals(AKY0005E_DUPLICATE_KEY_NAME,e.getReason());
			}
		});
	}
	

	@Test
	public void can_remove_access_key() {
		
		AccessKeyData key = newAccessKey()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(AccessKeyName.valueOf("revoke"))
							.withMethods("put","post","get")
							.withPaths("/foo","/bar")
							.withDescription("Unittest access key")
							.build();
		transaction(() -> {
			String token = service.createAccessKey(key);
			assertNotNull(token);
		});
				
		transaction(() -> {
			AccessKeyData created = service.getAccessKey(key.getAccessKeyId());
			assertEquals(key.getAccessKeyId(),created.getAccessKeyId());
			assertEquals(key.getAccessKeyName(),created.getAccessKeyName());
			assertEquals(key.getDescription(),created.getDescription());
			assertEquals(key.getMethods(),created.getMethods());
			assertEquals(key.getPaths(),created.getPaths());
			assertNotNull(created.getDateCreated());
			
		});

		transaction(() -> {
			service.removeAccessKey(key.getAccessKeyId());
		});
		
		transaction(() -> {
			try {
				service.getAccessKey(key.getAccessKeyId());
				fail("Exception expected!");
			} catch(EntityNotFoundException e) {
				assertEquals(AKY0001E_ACCESS_KEY_NOT_FOUND,e.getReason());
			}
		});
		
		AccessKeyEvent event = captor.getValue();
		assertTrue(event.isRevoked());
		assertEquals(key.getAccessKeyId(),event.getAccessKeyId());
		assertEquals(key.getAccessKeyName(),event.getAccessKeyName());
		
	}
	
	@Test
	public void can_update_access_key_description() {
		AccessKeyData key = newAccessKey()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(AccessKeyName.valueOf("description_test"))
							.withDescription("Unittest access key")
							.build();
		transaction(() -> {
			String token = service.createAccessKey(key);
			assertNotNull(token);
		});
		
		transaction(() -> {
			AccessKeyData read = service.getAccessKey(key.getAccessKeyId());
			assertEquals("Unittest access key",read.getDescription());
			service.updateAccessKey(key.getAccessKeyId(), "new description");
		});
		
		transaction(() -> {
			AccessKeyData read = service.getAccessKey(key.getAccessKeyId());
			assertEquals("new description",read.getDescription());
		});

	}
	
	@Test
	public void removing_an_non_existent_accesskey_creates_no_error() {
		AccessKeyId keyId = randomAccessKeyId();
		transaction(() -> {
			service.removeAccessKey(keyId);
		});
	}
	
}
