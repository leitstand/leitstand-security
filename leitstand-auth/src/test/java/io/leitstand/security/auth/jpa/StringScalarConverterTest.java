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
package io.leitstand.security.auth.jpa;

import static java.util.Arrays.asList;
import static java.util.UUID.randomUUID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Collection;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.UserName;

@RunWith(Parameterized.class)
public class StringScalarConverterTest {
	@Parameters
	public static Collection<Object[]> adapters(){
		Object[][] adapters = new Object[][]{
			{new UserNameConverter(),		"unit-user", new UserName("unit-user")},
		};
		return asList(adapters);
	}
	
	
	private AttributeConverter<Scalar<String>,String> converter;
	private Scalar<String> scalar;
	private String value;
	
	public StringScalarConverterTest(AttributeConverter<Scalar<String>,String> converter,
								     String value,
								     Scalar<String> scalar) {
		this.converter = converter;
		this.value = value;
		this.scalar = scalar;
		
	}
	
	@Test
	public void empty_string_is_mapped_to_null() throws Exception {
		assertNull(converter.getClass().getSimpleName(), 
				   converter.convertToEntityAttribute(""));
	}
	
	@Test
	public void null_string_is_mapped_to_null() throws Exception {
		assertNull(converter.getClass().getSimpleName(),
				   converter.convertToEntityAttribute(null));
	}
	
	@Test
	public void adapt_from_db() throws Exception{
		assertEquals(converter.getClass().getSimpleName(),
					 scalar,converter.convertToEntityAttribute(value));
	}
	
	@Test
	public void adapt_to_db() throws Exception {
		assertEquals(converter.getClass().getSimpleName(),
					 value,converter.convertToDatabaseColumn(scalar));
	}
	
	@Test
	public void null_scalar_is_mapped_to_null() throws Exception{
		assertNull(converter.convertToEntityAttribute(null));
	}
	
	@Test
	public void jpa_converter_annotation_present() {
		assertTrue(converter.getClass().isAnnotationPresent(Converter.class));
	}
}
