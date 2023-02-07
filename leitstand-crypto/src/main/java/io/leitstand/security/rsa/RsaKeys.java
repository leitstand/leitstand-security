package io.leitstand.security.rsa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

import io.leitstand.commons.etc.FileExporter;
import io.leitstand.commons.etc.FileProcessor;

/**
 * A RSA utility for generating key pairs as well as storing a key pair into a PEM file and reading a key pair from a PEM file.
 */
public final class RsaKeys {

    private static final String RSA_ALGORITHM = "RSA";
    
    public static final FileProcessor<KeyPair> PEM_FILE_PROCESSOR = new FileProcessor<KeyPair>() {

        public KeyPair process(Reader reader) throws IOException {
            return readRsaKeyPair(reader);
        }
        
    };
    
   
    private static class PemReader {
    
        private PrivateKey p;
        private List<PublicKey> q;
        
        PemReader(Reader reader) throws Exception{
            KeyFactory f = KeyFactory.getInstance(RSA_ALGORITHM);
            q = new LinkedList<>();
            try(BufferedReader lines = new BufferedReader(reader)){
                String line = lines.readLine();
                while (line != null) {
                    if (line.startsWith("-")) {
                        byte[] k = readEncodedKey(lines);
                        if (line.indexOf("PRIVATE KEY") >= 0) {
                            p = f.generatePrivate(new PKCS8EncodedKeySpec(k,RSA_ALGORITHM));
                        } else {
                            q.add(f.generatePublic(new X509EncodedKeySpec(k,RSA_ALGORITHM)));
                        }
                    }
                    line = lines.readLine();
                    
                }
            }
        }

        private byte[] readEncodedKey(BufferedReader lines) throws IOException{
            String line = lines.readLine();
            StringBuilder b = new StringBuilder();
            while (!line.startsWith("-")) {
                b.append(line);
                line = lines.readLine();
            }
            return Base64.getDecoder().decode(b.toString());
        }
        
        PrivateKey getPrivateKey() {
            return p;
        }
        
        PublicKey getPublicKey() {
            if (q.isEmpty()){
                return null;
            }
            return q.get(0);
        }
        
    }
    
    private static class PemWriter {
        
        private Writer writer;
        
        PemWriter(Writer writer){
            this.writer = writer;
        }
        
        void write(PrivateKey k) throws IOException{
            PKCS8EncodedKeySpec encoding = new PKCS8EncodedKeySpec(k.getEncoded());
            String encoding64 = Base64.getEncoder().encodeToString(encoding.getEncoded());
            println("-----BEGIN RSA PRIVATE KEY-----");
            writeEncodedKey(encoding64);
            println("-----END RSA PRIVATE KEY-----");
        }
        
        void write(PublicKey k) throws IOException{
            X509EncodedKeySpec encoding = new X509EncodedKeySpec(k.getEncoded());
            String encoding64 = Base64.getEncoder().encodeToString(encoding.getEncoded());
            println("-----BEGIN CERTIFICATE-----");
            writeEncodedKey(encoding64);
            println("-----END CERTIFICATE-----");           
        }
        
        private void writeEncodedKey(String s) throws IOException{
            // Divide s in lines of 65 characters length each.
            int i=0;
            while(s.length() > i+65) {
                println(s.substring(i,i+65));
                i+=65;
            }
            if (i < s.length()) {
                println(s.substring(i));
            }
        }
        
        private void println(String s) throws IOException{
            writer.write(s);
            writer.write("\n");
        }
        
    }
    
    /**
     * Generates a RSA key pair
     * @param keySize the key size in bits
     * @return the generated key pair
     */
    public static KeyPair generateRsaKeyPair(int keySize) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            generator.initialize(keySize);
            return generator.generateKeyPair();    
        } catch (Exception e) {
            throw new  RsaException("Cannot genrate RSA key pair",e);
        }
    }
    
    /**
     * Reads a key pair in PEM format from the given reader.
     * @param r the key pair in PEM format
     * @return the read key pair
     * @throws RsaException if the key pair cannot be read
     */
    public static KeyPair readRsaKeyPair(Reader r) {
        try {
            PemReader pem = new PemReader(r);
            return new KeyPair(pem.getPublicKey(),pem.getPrivateKey());
        } catch (Exception e) {
            throw new RsaException("Cannot read RSA key pair",e);
        }
    }
    
    /**
     * Writes the key pair in PEM format to the given writer.
     * @param p the key pair
     * @param w the target writer
     */
    public static void storeRsaKeyPair(KeyPair p, Writer w) {
        assertRsaKeyPair(p);
        try {
            PemWriter pem = new PemWriter(w);
            pem.write(p.getPrivate());
            pem.write(p.getPublic());
        } catch (Exception e) {
            throw new RsaException("Cannot store RSA key pair", e); 
        }
    }
    
    /**
     * Creates a key pair exporter.
     * @param p the key pair to be exported.
     * @return
     */
    public static FileExporter exportKeyPair(KeyPair p) {
        return w -> {
            storeRsaKeyPair(p, w);
        };
    }
    
    private static void assertRsaKeyPair(KeyPair p) {
        if (!RSA_ALGORITHM.equals(p.getPrivate().getAlgorithm())){
            throw new RsaException("Key pair is no RSA key pair!");
        }
    }
    
    private RsaKeys() {
        // No instances allowed.
    }
    
}
