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
/**
 * Contains the login audit log data model and service implementations.
 * <p>
 * All log records are written to a database.
 * The secret to sign all log records is read from the <code>login.record.secret</code> property.
 * This property is either specified as system property or read from the <code>/etc/rbms/login-audit-log.properties</code> file,
 * with system property having a precedence over the config file.
 * The property value is Base64 encoded and encrypted with the {@link MasterSecret}.
 */
package io.leitstand.security.login.log.model;
