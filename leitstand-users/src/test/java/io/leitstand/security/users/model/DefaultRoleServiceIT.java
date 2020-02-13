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
package io.leitstand.security.users.model;

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.users.model.Role.findRoleById;
import static io.leitstand.security.users.service.ReasonCode.IDM0006E_ROLE_NOT_FOUND;
import static io.leitstand.security.users.service.ReasonCode.IDM0010I_ROLE_REMOVED;
import static io.leitstand.security.users.service.ReasonCode.IDM0100E_CANNOT_ADD_SYSTEM_ROLE;
import static io.leitstand.security.users.service.ReasonCode.IDM0101E_CANNOT_UPDATE_SYSTEM_ROLE;
import static io.leitstand.security.users.service.ReasonCode.IDM0102E_CANNOT_REMOVE_SYSTEM_ROLE;
import static io.leitstand.security.users.service.RoleId.randomRoleId;
import static io.leitstand.security.users.service.RoleName.roleName;
import static io.leitstand.security.users.service.RoleSettings.newRoleSettings;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.reason;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import io.leitstand.commons.ConflictException;
import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.messages.Message;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Repository;
import io.leitstand.security.users.service.RoleId;
import io.leitstand.security.users.service.RoleSettings;

public class DefaultRoleServiceIT extends UsersIT{
	
	@Rule
	public ExpectedException exception = ExpectedException.none();

	private static final RoleId SYSTEMROLE_ID = randomRoleId();
	
	private DefaultRoleService service;
	private Messages messages;
	private ArgumentCaptor<Message> message;

	@Before
	public void initTestResources() {
		Repository repository = new Repository(getEntityManager());
		messages = mock(Messages.class);
		message = ArgumentCaptor.forClass(Message.class);
		doNothing().when(messages).add(message.capture());
		service = new DefaultRoleService(repository,messages);
		
		transaction(()->{
			Role admin = repository.addIfAbsent(findRoleById(SYSTEMROLE_ID),
											    ()-> (new Role(SYSTEMROLE_ID,roleName("system-role"))));
			admin.setScopes(asSet("admin"));
			admin.setSystemRole(true);
		});
		
	}
	
	@Test
	public void find_role_by_id() {
		transaction(()->{
			RoleSettings role = service.getRole(SYSTEMROLE_ID);
			assertNotNull(role);
			assertEquals(SYSTEMROLE_ID,role.getRoleId());
			assertEquals(roleName("system-role"),role.getRoleName());
			assertEquals(asSet("admin"),role.getScopes());
			assertTrue(role.isSystemRole());
		});
		
	}
	

	@Test
	public void find_role_by_name() {
		transaction(()->{
			RoleSettings role = service.getRole(roleName("system-role"));
			assertNotNull(role);
			assertEquals(SYSTEMROLE_ID,role.getRoleId());
			assertEquals(roleName("system-role"),role.getRoleName());
			assertEquals(asSet("admin"),role.getScopes());
			assertTrue(role.isSystemRole());
		});
		
	}
	
	@Test
	public void cannot_add_system_role() {
		exception.expect(UnprocessableEntityException.class);
		exception.expect(reason(IDM0100E_CANNOT_ADD_SYSTEM_ROLE));
		
		transaction(()->{
			RoleSettings role = newRoleSettings()
								.withRoleName(roleName("unit-test"))
								.withSystemRole(true)
								.build();
			service.storeRole(role);		
		});
	}
		
	@Test
	public void cannot_modify_system_role() {	
		transaction(()->{
			exception.expect(ConflictException.class);
			exception.expect(reason(IDM0101E_CANNOT_UPDATE_SYSTEM_ROLE));
			
			RoleSettings role = newRoleSettings()
							    .withRoleId(SYSTEMROLE_ID)
								.withRoleName(roleName("unit-test"))
								.build();
			service.storeRole(role);		
		});
	}
	
	@Test
	public void cannot_remove_system_role_by_id() {	
		transaction(()->{
			exception.expect(ConflictException.class);
			exception.expect(reason(IDM0102E_CANNOT_REMOVE_SYSTEM_ROLE));

			service.removeRole(SYSTEMROLE_ID);
		});
	}

	
	@Test
	public void cannot_remove_system_role_by_name() {
		
		transaction(()->{
			exception.expect(ConflictException.class);
			exception.expect(reason(IDM0102E_CANNOT_REMOVE_SYSTEM_ROLE));

			service.removeRole(roleName("system-role"));
		});
	}
	
	@Test
	public void update_existing_role() {
		RoleSettings role = newRoleSettings()
							.withRoleName(roleName("update-role"))
							.build();
		transaction(()->{
			service.storeRole(role);	
		});
		
		RoleSettings update = newRoleSettings()
							  .withRoleId(role.getRoleId())
							  .withRoleName(roleName("renamed"))
							  .withScopes(asSet("foo","bar"))
							  .withDescription("Faked unit test role")
							  .build();
			
		transaction(() ->{
			boolean created = service.storeRole(update);
			assertFalse(created);
		});
		
		transaction(() -> {
			RoleSettings updated = service.getRole(update.getRoleId());
			assertEquals(update,updated);
		});
		
	}
	

	@Test
	public void add_new_role() {
		RoleSettings role = newRoleSettings()
							.withRoleName(roleName("new-role"))
							.build();
		transaction(()->{
			boolean created = service.storeRole(role);	
			assertTrue(created);
		});
		
		transaction(()->{
			RoleSettings created = service.getRole(roleName("new-role"));
			assertEquals(role,created);
		});
		
	}
	

	
	@Test
	public void remove_role() {
		RoleSettings role = newRoleSettings()
							.withRoleName(roleName("remove-role"))
							.build();
		transaction(()->{
			service.storeRole(role);	
		});
		
		transaction(()->{
			service.removeRole(roleName("remove-role"));
			assertEquals(IDM0010I_ROLE_REMOVED.getReasonCode(),message.getValue().getReason());
		});
		
	}

	
	@Test
	public void do_nothing_when_removing_unknown_role() {
		transaction(()->{
			service.removeRole(roleName("unknown"));
			verify(messages,never()).add(any(Message.class));
		});
		
		transaction(()->{
			service.removeRole(randomRoleId());
			verify(messages,never()).add(any(Message.class));
		});
	}
	
	@Test
	public void throw_EntityNotFoundException_when_attempting_to_read_unknown_role_id() {
		transaction(() -> {
			exception.expect(EntityNotFoundException.class);
			exception.expect(reason(IDM0006E_ROLE_NOT_FOUND));
			service.getRole(randomRoleId());
		});
	}
	
	@Test
	public void throw_EntityNotFoundException_when_attempting_to_read_unknown_role_name() {
		transaction(() -> {
			exception.expect(EntityNotFoundException.class);
			exception.expect(reason(IDM0006E_ROLE_NOT_FOUND));
			service.getRole(roleName("unknown"));
		});
	}
	
	
	
}
