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
package io.leitstand.security.auth.jsonb;

import static java.util.Arrays.asList;
import static java.util.UUID.randomUUID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Collection;

import javax.json.bind.adapter.JsonbAdapter;
import javax.json.bind.annotation.JsonbTypeAdapter;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskeys.AccessKeyId;

@RunWith(Parameterized.class)
public class StringScalarAdapterTest {
	@Parameters
	public static Collection<Object[]> adapters(){
		String uuid = randomUUID().toString();
		Object[][] adapters = new Object[][]{
			{new UserNameAdapter(),		"unit-user", new UserName("unit-user")},
			{new AccessKeyIdAdapter(),	uuid, 		 new AccessKeyId(uuid)},
		};
		return asList(adapters);
	}
	
	
	private JsonbAdapter<Scalar<String>,String> adapter;
	private Scalar<String> scalar;
	private String value;
	
	public StringScalarAdapterTest(JsonbAdapter<Scalar<String>,String> adapter,
								   String value,
								   Scalar<String> scalar) {
		this.adapter = adapter;
		this.value = value;
		this.scalar = scalar;
		
	}
	
	@Test
	public void empty_string_is_mapped_to_null() throws Exception {
		assertNull(adapter.getClass().getSimpleName(), 
				   adapter.adaptFromJson(""));
	}
	
	@Test
	public void null_string_is_mapped_to_null() throws Exception {
		assertNull(adapter.getClass().getSimpleName(),
				   adapter.adaptFromJson(null));
	}
	
	@Test
	public void adapt_from_json() throws Exception{
		assertEquals(adapter.getClass().getSimpleName(),
					 scalar,adapter.adaptFromJson(value));
	}
	
	@Test
	public void adapt_to_json() throws Exception {
		assertEquals(adapter.getClass().getSimpleName(),
					 value,adapter.adaptToJson(scalar));
	}
	
	@Test
	public void null_scalar_is_mapped_to_null() throws Exception{
		assertNull(adapter.adaptToJson(null));
	}
	
	@Test
	public void jsonb_adapter_annotation_present() {
		assertTrue(scalar.getClass().isAnnotationPresent(JsonbTypeAdapter.class));
		assertSame(adapter.getClass(),scalar.getClass().getAnnotation(JsonbTypeAdapter.class).value());
	}
}
