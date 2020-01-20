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
 * Contains the model and service implementations of the built-in identity management.
 * <p>
 * The built-in management system is a Java EE <code>IdentityStore</code> implementation,
 * thereby forming the basis for all user credentials validation.
 * Alternative identity store implementations can be enabled by the CDI <code>{@literal @Alternative}</code> mechanism. 
 * </p>
 * The built-in identity management stores all users and passwords in relational database.
 * Passwords are stored as salted hash values. 
 * The password hashes are computed with <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a> 
 * and <a href="https://en.wikipedia.org/wiki/HMAC">HMAC-SHA256</a> as pseudo random function.
 * The salt values are computed with a cryptographically secure pseudorandom number generator.
 * The number of iterations is set to 10000.
 */
package io.leitstand.security.users.model;
