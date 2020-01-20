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
 * Contains the master secret to encrypt and decrypt confidential information such as the secret to sign access tokens as an example.
 * <p>
 * The {@link MasterSecret} leverages the <a href="http://en.wikipedia.org">Advanced Encryption Standard (AES)</a> to encrypt sensitive information.
 * The <code>master.secret</code> and the <code>master.iv</code> properties set the AES secret and initialization vector (IV).
 * Both properties can be either specified as system properties or in the <code>/etc/rbms/master.secret</code> file, 
 * with system properties having precedence over the configuration file. The specified values must be Base64 encoded.
 * <p>
 * AES requires a key and IV length of 16 bytes. This is accomplished by computing the MD5 hash values from the specified properties and 
 * using the 16 MD5 bytes as key and IV respectively. If no IV is specified, the IV defaults to the 16 bytes of the MD5 of the secret MD5 hash value.
 * <p>
 * If no secret is specified, the master secret key defaults to <i>changeit</i>.
 */
package io.leitstand.security.crypto;
