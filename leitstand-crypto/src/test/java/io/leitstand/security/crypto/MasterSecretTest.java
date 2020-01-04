/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.crypto;

import static io.leitstand.commons.etc.Environment.emptyEnvironment;
import static io.leitstand.commons.model.ByteArrayUtil.encodeBase64String;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.crypto.MasterSecret.RBMS_MASTER_SECRET_FILE_NAME;
import static io.leitstand.security.crypto.MasterSecret.RBMS_PROPERTY_MASTER_IV;
import static io.leitstand.security.crypto.MasterSecret.RBMS_PROPERTY_MASTER_SECRET;
import static org.junit.Assert.assertArrayEquals;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;

import io.leitstand.commons.etc.Environment;
import io.leitstand.commons.etc.FileProcessor;

public class MasterSecretTest {

	
	private MasterSecret defaultMaster;
	private MasterSecret cfgMaster;
	
	static String base64encoded(String secret) {
		return encodeBase64String(toUtf8Bytes(secret));
	}
	
	@Before
	public void initMasterSecrets() throws IOException{
		// Initialize default master secret
		Environment env = emptyEnvironment();
		defaultMaster = new MasterSecret(env);
		defaultMaster.init();
		
		Properties properties = new Properties();
		properties.put(RBMS_PROPERTY_MASTER_SECRET, base64encoded("properties-secret"));
		properties.put(RBMS_PROPERTY_MASTER_IV, base64encoded("properties-iv"));
		Environment propertiesEnv = mock(Environment.class);
		when(propertiesEnv.loadFile(eq(RBMS_MASTER_SECRET_FILE_NAME),isA(FileProcessor.class))).thenReturn(properties);
		cfgMaster = new MasterSecret(propertiesEnv);
		cfgMaster.init();
		
	}
	
	@Test
	public void default_encryption_decryption_results_in_same_plaintext(){
		byte[] plain   = toUtf8Bytes("abcdefghijklmnopqrstuvwxyz0123456789");
		byte[] cipher  = defaultMaster.encrypt(plain);
		byte[] decrypt = defaultMaster.decrypt(cipher);
		assertArrayEquals(plain,decrypt);
	}
	
	
	@Test
	public void configured_encryption_decryption_results_in_same_plaintext(){
		byte[] plain   = toUtf8Bytes("abcdefghijklmnopqrstuvwxyz0123456789");
		byte[] cipher  = cfgMaster.encrypt(plain);
		byte[] decrypt = cfgMaster.decrypt(cipher);
		assertArrayEquals(plain,decrypt);
	}
	
}
