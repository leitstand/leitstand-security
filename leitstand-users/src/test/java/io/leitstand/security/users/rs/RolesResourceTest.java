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
package io.leitstand.security.users.rs;

import static io.leitstand.security.users.service.RoleId.randomRoleId;
import static io.leitstand.security.users.service.RoleName.roleName;
import static io.leitstand.security.users.service.RoleSettings.newRoleSettings;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.reason;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.ws.rs.core.Response;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.ConflictException;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.rs.ReasonCode;
import io.leitstand.security.users.service.RoleId;
import io.leitstand.security.users.service.RoleName;
import io.leitstand.security.users.service.RoleService;
import io.leitstand.security.users.service.RoleSettings;

@RunWith(MockitoJUnitRunner.class)
public class RolesResourceTest {
	
	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Mock
	private RoleService service;
	
	@Mock
	private Messages messages;
	
	@InjectMocks
	private RolesResource resource = new RolesResource();
	
	
	@Test
	public void get_roles() {
		resource.getRoles();
		verify(service).getRoles();
	}

	@Test
	public void get_role_by_name() {
		RoleName role = roleName("foo");
		resource.getRole(role);
		verify(service).getRole(role);
	}

	@Test
	public void get_role_by_id() {
		RoleId role = randomRoleId();
		resource.getRole(role);
		verify(service).getRole(role);
	}
	
	@Test
	public void remove_role_by_name() {
		when(messages.isEmpty()).thenReturn(true);
		RoleName role = roleName("foo");
		Response response = resource.removeRole(role);
		assertEquals(204,response.getStatus());
		verify(service).removeRole(role);
	}

	@Test
	public void remove_role_by_id() {
		RoleId role = randomRoleId();
		Response response = resource.removeRole(role);
		assertEquals(200,response.getStatus());
		verify(service).removeRole(role);
	}
	
	@Test
	public void cannot_modify_role_id() {
		exception.expect(ConflictException.class);
		exception.expect(reason(ReasonCode.VAL0003E_IMMUTABLE_ATTRIBUTE));
		
		RoleId roleId = randomRoleId();
		RoleSettings role = newRoleSettings().build();
		resource.storeRole(roleId,role);
	}

	@Test
	public void send_created_response_when_adding_new_role() {
		RoleSettings role = newRoleSettings().build();
		when(service.storeRole(role)).thenReturn(true);
		
		Response response = resource.storeRole(role);
		
		assertEquals(201,response.getStatus());
	}

	@Test
	public void send_success_response_when_updating_existing_role() {
		RoleSettings role = newRoleSettings().build();
		
		Response response = resource.storeRole(role);
		
		assertEquals(200,response.getStatus());
		verify(service).storeRole(role);
	}
	
	
	
	
}

