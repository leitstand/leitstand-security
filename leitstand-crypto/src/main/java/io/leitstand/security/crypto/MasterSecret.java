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
package io.leitstand.security.crypto;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.etc.FileProcessor.properties;
import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.crypto.SecureHashes.md5;
import static java.lang.System.arraycopy;
import static java.util.logging.Level.FINER;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.util.Properties;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.commons.etc.Environment;

/**
 * A service to decrypt sensitive information, such as the key to sign access tokens for example.
 * <p>
 * The <code>MasterSecret</code> leverages <a href="http://en.wikipedia.org">Advanced Encryption Standard (AES)</a> to encrypt sensitive information. 
 * By that, it is expected that the information was encrypted with AES before.
 * The <code>master.secret</code> and the <code>master.iv</code> properties set the ASE secret and initialization vector (IV).
 * Both properties can be either specified as system properties or in the <code>/etc/rbms/master.secret</code> file, 
 * with system properties having precedence over the configuration file. The specified values must be Base64 encoded.
 * <p>
 * AES requires a key and IV length of 16 bytes. This is accomplished by computing the MD5 hash values from the specified properties and 
 * using the 16 MD5 bytes as key and IV respectively. If no IV is specified, the IV defaults to the MD5 of the secret MD5 hash value.
 * <p>
 * If no secret is specified, the master secret key defaults to <i>changeit</i>.
 */
@ApplicationScoped
public class MasterSecret {

	private static final Logger LOG = Logger.getLogger(MasterSecret.class.getName());
	static final String RBMS_MASTER_SECRET_FILE_NAME = "master.secret";
	static final String RBMS_PROPERTY_MASTER_SECRET  = "master.secret";
	static final String RBMS_PROPERTY_MASTER_IV	     = "master.iv";

	private Environment env;
	
	private byte[] master;
	private byte[] iv;
	
	protected MasterSecret() {
		// CDI
	}
	
	@Inject
	public MasterSecret(Environment env) {
		this.env = env;
	}
	
	@PostConstruct
	public void init() {
		this.master = new byte[16];
		this.iv     = new byte[16];
		
		// Load the master.secret file. 
		// Defaults to empty properties file, if file does not exist.
		Properties masterSecret = env.loadFile(RBMS_MASTER_SECRET_FILE_NAME, 
											   properties());
		
		// Read configured secret
		String secret64 = masterSecret.getProperty(RBMS_PROPERTY_MASTER_SECRET,
												   getSystemProperty(RBMS_PROPERTY_MASTER_SECRET));
		if(isNonEmptyString(secret64)) {
 			byte[] secretMd5 = md5().hash(decodeBase64String(secret64));
 			byte[] secretMd5Md5 = md5().hash(secretMd5);
 			// Use first 16 bytes of MD5 as secret key
 			arraycopy(secretMd5,
 					  0,
 					  master,
 					  0,
 					  16);
 			// Use last 16 bytes of MD5 as default IV.
 			arraycopy(secretMd5Md5,
					  0,
					  iv,
					  0,
					  16);
 		} else {
 			byte[] defaultMd5 = md5().hash("changeit");
 			byte[] defaultMd5Md5 = md5().hash(defaultMd5);
 			// Use first 16 bytes of MD5 as secret key
 			arraycopy(defaultMd5,
					  0,
					  master,
					  0,
					  16);
 			// Use last 16 bytes of MD5 as default IV.
 			arraycopy(defaultMd5Md5,
					  0,
					  iv,
					  0,
					  16);
 		}

		// Overwrite iv, if another iv is configured
 		String iv64 = masterSecret.getProperty(RBMS_PROPERTY_MASTER_IV,
 											   getSystemProperty(RBMS_PROPERTY_MASTER_IV));
 		if(isNonEmptyString(iv64)) {
 			arraycopy(md5().hash(decodeBase64String(iv64)),
					  0,
					  iv,
					  0,
					  16);
 		}
		
	}
	
	/**
	 * Decrypts the specified cipher text.
	 * @param ciphertext - the cipher text to be decrypted
	 * @return the plain text
	 * @throws MasterSecretException if decryption fails
	 */
	public byte[] decrypt(byte[] ciphertext){
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(DECRYPT_MODE, 
						new SecretKeySpec(master,"AES"),
						new IvParameterSpec(iv));
			return cipher.doFinal(ciphertext);
		} catch(Exception e){
			LOG.fine(() -> "Cannot decrypt ciphertext: "+e.getMessage());
			LOG.log(FINER, e.getMessage(), e);
			throw new MasterSecretException(e); 
		}
	}	

	/**
	 * Converts the given plain text to UTF-8 bytes and encrypts it.
	 * @param plaintext - the plain text to be encrypted
	 * @return the cipher text
	 * @throws MasterSecretException if encryption fails
	 */
	public byte[] encrypt(String plaintext){
		return encrypt(toUtf8Bytes(plaintext));
	}
	
	/**
	 * Encrypts the given plain test.
	 * @param plaintext - the plain text to be encrypted
	 * @return the cipher text
	 * @throws MasterSecretException if encryption fails
	 */
	public byte[] encrypt(byte[] plaintext) {
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(ENCRYPT_MODE, 
						new SecretKeySpec(master,"AES"),
						new IvParameterSpec(iv));
			return cipher.doFinal(plaintext);
		} catch(Exception e){
			LOG.fine(() -> "Cannot encrypt ciphertext: "+e.getMessage());
			LOG.log(FINER, e.getMessage(), e);
			throw new MasterSecretException(e);
		}		
	}
	
}
