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
package io.leitstand.security.auth;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * The <code>Scopes</code> annotation declares the scopes a Leitstand REST resource or service belongs to.
 * Scopes are also the basis for authorization as permissions are granted on a per-scope basis.
 * <p>
 * Scopes can be declared on type and method level. 
 * The scopes declared on a method-level extend the scopes declared on type-level without replacing them.
 * Thus scopes defined on method-level grant <em>additional</em> scopes access to the respective operation.
 * <p>
 * Lets look into an example to understand this important concept in detail.
 * The inventory defines the following scopes among others:
 * <ul>
 * 	<li><em>ivt</em>scope grants unrestricted access to all inventory resources.</li>
 *  <li><em>ivt.read</em> scope grants readonly access to all inventory resources.</li>
 *  <li><em>ivt.element</em> scope grants unrestricted access to all inventory element resources.</li>
 * </ul>
 * The <code>ElementSettingsResource</code> uses these scopes as listed below.
 * <pre>
 * {@code
 * @Resource
 * @Scopes({"ivt","ivt.element"})
 * public class ElementSettingsResource{
 * 
 *  @GET
 *  @Path("/{element:"+UUID_PATTERN+"}/settings")
 *  @Scopes({"ivt.read"})
 *  public ElementSettings getElementSettings(@Valid @PathParam("element") ElementId element){
 *    ...
 *  }
 *  @PUT
 *  @Path("/{element:"+UUID_PATTERN+"}/settings")
 *  public Response storeElementSettings(@Valid @PathParam("element") ElementId element, 
 *                                       @Valid ElementSettings settings){
 *  ...
 *  }
 *  ...
 *  }
 * }
 * </pre>
 * The resource grants access to all its operations for users with with access to the <em>ivt</em> and <em>ivt.element</em> scopes.
 * The GET operation declares the <em>ivt.read</em> scope additionally which allows users with access to the <em>ivt.read</em> scope to read the element settings.
 * The PUT operation, however, does not declare an additional scope, which is why only users with access to the <em>ivt</em> and <em>ivt.element</em> scopes are allowed to store element settings.
 * 
 */
@Retention(RUNTIME)
@Target({TYPE,METHOD})
@Inherited
public @interface Scopes {
	/**
	 * Returns the scopes that are allowed to access this resource or service.
	 * @return the scopes that are allowed to access this resource or service.
	 */
	String[] value();
}
