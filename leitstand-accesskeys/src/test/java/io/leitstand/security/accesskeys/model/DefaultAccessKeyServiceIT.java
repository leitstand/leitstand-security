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
package io.leitstand.security.accesskeys.model;

import static io.leitstand.security.accesskeys.service.AccessKeyName.accessKeyName;
import static io.leitstand.security.accesskeys.service.AccessKeySettings.newAccessKeySettings;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0001E_ACCESS_KEY_NOT_FOUND;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0005E_DUPLICATE_KEY_NAME;
import static io.leitstand.security.auth.accesskeys.AccessKeyId.randomAccessKeyId;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.reason;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

import java.util.Date;
import java.util.List;

import javax.enterprise.event.Event;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.mockito.ArgumentCaptor;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UniqueKeyConstraintViolationException;
import io.leitstand.commons.etc.Environment;
import io.leitstand.commons.model.ObjectUtil;
import io.leitstand.commons.model.Repository;
import io.leitstand.security.accesskeys.event.AccessKeyEvent;
import io.leitstand.security.accesskeys.service.AccessKeyInfo;
import io.leitstand.security.accesskeys.service.AccessKeySettings;
import io.leitstand.security.auth.accesskeys.AccessKeyId;
import io.leitstand.security.auth.accesskeys.ApiAccessKey;

public class DefaultAccessKeyServiceIT extends AccessKeysIT{

    @Rule
    public TemporaryFolder leitstandHome = new TemporaryFolder();
    
    @Rule
    public ExpectedException exception = ExpectedException.none();
    
	private Repository repository;
	private DefaultAccessKeyService service;
	private ArgumentCaptor<AccessKeyEvent> captor;
	private DefaultApiAccessKeyService encoder;
	
	@Before
	public void initResources() {
		repository = new Repository(getEntityManager());
		Event event = mock(Event.class);
		AccessKeyConfig config = new AccessKeyConfig(new Environment(leitstandHome.getRoot()));
		captor = ArgumentCaptor.forClass(AccessKeyEvent.class);
		doNothing().when(event).fire(captor.capture());
		encoder = new DefaultApiAccessKeyService(config);
		service = new DefaultAccessKeyService(repository,
											  getDatabase(),
											  encoder,
											  event);
	}
	
	@Test
	public void fire_EntityNotFoundException_if_access_key_does_not_exist() {
		exception.expect(EntityNotFoundException.class);
		exception.expect(reason(AKY0001E_ACCESS_KEY_NOT_FOUND));
		service.getAccessKey(randomAccessKeyId());
	}
	
	@Test
	public void can_create_new_access_key_without_scopes() {
		
		AccessKeySettings key = newAccessKeySettings()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(accessKeyName("general"))
							.withDateCreated(new Date())
							.withDescription("Unittest access key")
							.build();
		String token = service.createAccessKey(key);
		assertNotNull(token);
		
		ApiAccessKey decoded = encoder.decode(token);
		assertEquals(key.getAccessKeyId(),decoded.getId());
		assertEquals(key.getAccessKeyName().toString(),decoded.getUserName().toString());
		
		AccessKeyEvent event = captor.getValue();
		assertTrue(event.isCreated());
		assertEquals(key.getAccessKeyId(),event.getAccessKeyId());
		assertEquals(key.getAccessKeyName(),event.getAccessKeyName());
		assertTrue(key.getScopes().isEmpty());
	}
	

	
	@Test
	public void can_create_new_access_key_with_scopes() {
		
		AccessKeySettings key = newAccessKeySettings()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(accessKeyName("method_path"))
							.withDateCreated(new Date())
							.withScopes("element","pod")
							.withDescription("Unittest access key")
							.build();
		String token = service.createAccessKey(key);
		assertNotNull(token);
		
		ApiAccessKey decoded = encoder.decode(token);
		assertEquals(key.getAccessKeyId(),decoded.getId());
		assertEquals(key.getAccessKeyName().toString(),decoded.getUserName().toString());
		assertEquals(ObjectUtil.asSet("element","pod"),key.getScopes());
		
		AccessKeyEvent event = captor.getValue();
		assertTrue(event.isCreated());
		assertEquals(key.getAccessKeyId(),event.getAccessKeyId());
		assertEquals(key.getAccessKeyName(),event.getAccessKeyName());

		
	}
	
	@Test
	public void cannot_create_keys_with_same_name() {
		
		AccessKeySettings key = newAccessKeySettings()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(accessKeyName("unique_test"))
							.withDateCreated(new Date())
							.withScopes("element","pod")
							.withDescription("Unittest access key")
							.build();
		transaction(() -> {
			String token = service.createAccessKey(key);
			assertNotNull(token);
		});
		
		transaction(() -> {
			exception.expect(UniqueKeyConstraintViolationException.class);
			exception.expect(reason(AKY0005E_DUPLICATE_KEY_NAME));
			service.createAccessKey(key);
		});
	}
	

	@Test
	public void can_remove_access_key() {
		
		AccessKeySettings key = newAccessKeySettings()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(accessKeyName("revoke"))
							.withScopes("element","pod")
							.withDescription("Unittest access key")
							.build();
		transaction(() -> {
			String token = service.createAccessKey(key);
			assertNotNull(token);
		});
				
		transaction(() -> {
			AccessKeySettings created = service.getAccessKey(key.getAccessKeyId());
			assertEquals(key.getAccessKeyId(),created.getAccessKeyId());
			assertEquals(key.getAccessKeyName(),created.getAccessKeyName());
			assertEquals(key.getDescription(),created.getDescription());
			assertEquals(key.getScopes(),created.getScopes());
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
				// Catch exception to not skip the test run.
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
		AccessKeySettings key = newAccessKeySettings()
							.withAccessKeyId(randomAccessKeyId())
							.withAccessKeyName(accessKeyName("description_test"))
							.withDescription("Unittest access key")
							.build();
		transaction(() -> {
			String token = service.createAccessKey(key);
			assertNotNull(token);
		});
		
		transaction(() -> {
			AccessKeySettings read = service.getAccessKey(key.getAccessKeyId());
			assertEquals("Unittest access key",read.getDescription());
			service.updateAccessKey(key.getAccessKeyId(), "new description");
		});
		
		transaction(() -> {
			AccessKeySettings read = service.getAccessKey(key.getAccessKeyId());
			assertEquals("new description",read.getDescription());
		});

	}
	
	@Test
	public void removing_an_non_existent_accesskey_creates_no_error() {
		AccessKeyId keyId = randomAccessKeyId();
		transaction(() -> {
			service.removeAccessKey(keyId);
		});
		assertTrue(captor.getAllValues().isEmpty());
	}
	
	static class TokenInspector {
	    String token;
	}
	
	@Test
	public void restore_revoked_access_key() {
	 
	    AccessKeySettings key = newAccessKeySettings()
	                        	.withAccessKeyId(randomAccessKeyId())
	                        	.withAccessKeyName(accessKeyName("restore_revoked"))
	                        	.withScopes("element","pod")
	                        	.withDescription("Unittest access key")
	                        	.build();
	    
	    TokenInspector inspector = new TokenInspector(); 
	    
	    // Create access key
	    transaction(() -> {
           inspector.token = service.createAccessKey(key);
           assertNotNull(inspector.token);
        });
               
	    // Revoke access key
	    transaction(() -> {
           service.removeAccessKey(key.getAccessKeyId());
        });

	    // Restore access key
        transaction(() -> {
            
            ApiAccessKey decoded = encoder.decode(inspector.token);
            AccessKeySettings restored = newAccessKeySettings()
                                     .withAccessKeyId(decoded.getId())
                                     .withAccessKeyName(accessKeyName(decoded.getUserName()))
                                     .withDateCreated(decoded.getDateCreated())
                                     .withScopes(decoded.getScopes())
                                     .build();
            
            
           String token = service.createAccessKey(restored);
           assertEquals(inspector.token,token);
        });

	}
	
	@Test
	public void filter_access_key_by_name() {
		AccessKeySettings key = newAccessKeySettings().withAccessKeyId(randomAccessKeyId())
								.withAccessKeyName(accessKeyName("test"))
								.withDateCreated(new Date())
								.build();
		transaction(() -> {
			service.createAccessKey(key);
		});
		
		transaction(() -> {
			List<AccessKeyInfo> keys = service.findAccessKeys("te.*");
			assertEquals(accessKeyName("test"), keys.get(0).getAccessKeyName());
		});
		
	}
	
}
