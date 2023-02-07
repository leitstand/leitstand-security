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

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.crypto.SecureHashes.sha3_256;
import static java.util.Arrays.copyOfRange;
import static java.util.Base64.getDecoder;
import static java.util.logging.Level.FINER;
import static java.util.logging.Logger.getLogger;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.commons.etc.Environment;
import io.leitstand.commons.etc.FileProcessor;

/**
 * The master secret allows protecting sensitive configuration settings using <em>AES</em> encryption
 * in CTR mode with a 128-bit key.
 * <p>
 * The master secret is stored base64-encoded in the <code>{LEITSTAND_ENV}/master.secret</code> file
 * and defaults to <em>changeit</em> if the file does not exist. 
 * <p>
 * The master secret computes a SHA3-256 hash from the given master secret and uses the first 16 bytes 
 * as key and the last 16 bytes as IV.
 */
@ApplicationScoped
public class MasterSecret {

	private static final Logger LOG = getLogger(MasterSecret.class.getName());
	public static final String LEITSTAND_MASTER_SECRET_FILE_NAME = "master.secret";

	private static final FileProcessor<byte[]> BASE_64_PROCESSOR = new FileProcessor<>() {

        @Override
        public byte[] process(Reader reader) throws IOException {
            BufferedReader lines = new BufferedReader(reader);
            String secret = lines.readLine();
            return getDecoder().decode(secret);
        }
	    
	};
	
	private Environment env;
	
	private byte[] key;
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
		// Read master secret from file
		byte[] masterSecret = env.loadConfig(LEITSTAND_MASTER_SECRET_FILE_NAME, 
										     BASE_64_PROCESSOR,
										     () -> toUtf8Bytes("changeit"));
		
		byte[] sha256 = sha3_256().hash(masterSecret);
		this.key = copyOfRange(sha256, 0, 16) ;
 		this.iv = copyOfRange(sha256,16,32);

	}
	
	/**
	 * Decrypts the specified cipher text.
	 * @param ciphertext the cipher text to be decrypted
	 * @return the plain text
	 * @throws MasterSecretException if decryption fails
	 */
	public byte[] decrypt(byte[] ciphertext){
		try{
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(DECRYPT_MODE, 
						new SecretKeySpec(key,"AES"),
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
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(ENCRYPT_MODE, 
						new SecretKeySpec(key,"AES"),
						new IvParameterSpec(iv));
			return cipher.doFinal(plaintext);
		} catch(Exception e){
			LOG.fine(() -> "Cannot encrypt ciphertext: "+e.getMessage());
			LOG.log(FINER, e.getMessage(), e);
			throw new MasterSecretException(e);
		}		
	}
	
}
