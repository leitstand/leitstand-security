package io.leitstand.security.rsa;

import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.rsa.RsaKeys.generateRsaKeyPair;
import static io.leitstand.security.rsa.RsaKeys.readRsaKeyPair;
import static io.leitstand.security.rsa.RsaKeys.storeRsaKeyPair;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.junit.Assert.assertEquals;
import static org.junit.rules.ExpectedException.none;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class RsaKeysTest {

    @Rule
    public ExpectedException exception = none();
    
    @Test
    public void raise_exception_when_storing_non_RSA_keypair() throws Exception{
        exception.expect(RsaException.class);
        KeyPair p = KeyPairGenerator.getInstance("DSA").generateKeyPair();
        StringWriter w = new StringWriter();
        storeRsaKeyPair(p,w);
    }
    
    
    @Test
    public void store_load_keypair() throws Exception{
        KeyPair p = generateRsaKeyPair(2048);
        
        // Encrypt plaintext with generated private key
        String plaintext = "plaintext";
        Cipher encrypt = Cipher.getInstance("RSA");
        encrypt.init(ENCRYPT_MODE, p.getPublic());
        byte[] ciphertext = encrypt.doFinal(toUtf8Bytes(plaintext));
        
        // Store and load keypair.
        StringWriter w = new StringWriter();
        storeRsaKeyPair(p, w);
        StringReader r = new StringReader(w.toString());
        System.out.println(w);
        KeyPair q = readRsaKeyPair(r);
        
        Cipher decrypt = Cipher.getInstance("RSA");
        decrypt.init(DECRYPT_MODE, q.getPrivate());
        String decrypted = fromUtf8Bytes(decrypt.doFinal(ciphertext));
        assertEquals(plaintext, decrypted);
    }
}
