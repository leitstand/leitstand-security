/*
 * Copyright 2022 RtBrick Inc.
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
package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.etc.FileProcessor.properties;
import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.security.crypto.SecureHashes.md5;
import static java.lang.System.arraycopy;
import static java.util.logging.Level.FINER;
import static java.util.logging.Logger.getLogger;
import static javax.crypto.Cipher.DECRYPT_MODE;

import java.util.Properties;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.Dependent;
import javax.inject.Inject;

import io.leitstand.commons.etc.Environment;
import io.leitstand.security.crypto.MasterSecretException;


@Dependent
class LegacyMasterSecret {

    private static final Logger LOG = getLogger(LegacyMasterSecret.class.getName());
    static final String RBMS_MASTER_SECRET_FILE_NAME = "master.secret";
    static final String RBMS_PROPERTY_MASTER_SECRET  = "master.secret";
    static final String RBMS_PROPERTY_MASTER_IV      = "master.iv";

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int AES_KEY_SIZE = 32;
    
    private Environment env;
    
    private byte[] master;
    private byte[] iv;
    
    protected LegacyMasterSecret() {
        // CDI
    }
    
    @Inject
    public LegacyMasterSecret(Environment env) {
        this.env = env;
    }
    
    @PostConstruct
    public void init() {
        this.master = new byte[AES_KEY_SIZE];
        this.iv     = new byte[GCM_IV_LENGTH];
        
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
            arraycopy(secretMd5,
                      0,
                      master,
                      0,
                      GCM_IV_LENGTH);
            arraycopy(secretMd5Md5,
                      0,
                      iv,
                      0,
                      GCM_IV_LENGTH);
        } else {
            byte[] defaultMd5 = md5().hash("changeit");
            byte[] defaultMd5Md5 = md5().hash(defaultMd5);
            arraycopy(defaultMd5,
                      0,
                      master,
                      0,
                      GCM_IV_LENGTH);
            arraycopy(defaultMd5Md5,
                      0,
                      iv,
                      0,
                      GCM_IV_LENGTH);
        }

        // Overwrite iv, if another iv is configured
        String iv64 = masterSecret.getProperty(RBMS_PROPERTY_MASTER_IV,
                                               getSystemProperty(RBMS_PROPERTY_MASTER_IV));
        if(isNonEmptyString(iv64)) {
            arraycopy(md5().hash(decodeBase64String(iv64)),
                      0,
                      iv,
                      0,
                      GCM_IV_LENGTH);
        }
        
    }
    
    public byte[] decrypt(byte[] ciphertext){
        try{
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(DECRYPT_MODE, 
                        new SecretKeySpec(master,"AES"),
                        new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
            return cipher.doFinal(ciphertext);
        } catch(Exception e){
            LOG.fine(() -> "Cannot decrypt ciphertext: "+e.getMessage());
            LOG.log(FINER, e.getMessage(), e);
            throw new MasterSecretException(e); 
        }
    }   
    
}