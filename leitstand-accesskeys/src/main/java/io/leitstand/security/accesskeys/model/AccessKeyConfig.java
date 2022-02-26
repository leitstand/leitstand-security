package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0100E_INVALID_ACCESSKEY;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0103E_CANNOT_SIGN_ACCESSKEY;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmac;
import static io.leitstand.security.rsa.RsaKeys.PEM_FILE_PROCESSOR;
import static io.leitstand.security.rsa.RsaKeys.exportKeyPair;
import static io.leitstand.security.rsa.RsaKeys.generateRsaKeyPair;
import static java.lang.String.format;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getUrlEncoder;
import static java.util.logging.Logger.getLogger;

import java.security.KeyPair;
import java.util.function.Supplier;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import com.nimbusds.jose.jwk.JWKSet;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.etc.Environment;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.jwt.Claims.Builder;
import io.leitstand.security.auth.jwt.DefaultRsaJwtService;
import io.leitstand.security.auth.jwt.JwtException;
import io.leitstand.security.auth.jwt.JwtService;
import io.leitstand.security.crypto.MasterSecretException;
import io.leitstand.security.crypto.Secret;
import io.leitstand.security.mac.MessageAuthenticationCode;

/**
 * Reads the API access key configurations and provides methods to sign and decode API access keys.
 * <p>
 * Leitstand API access keys are JSON Web Tokens and signed with the <em>RS256</em> JWS algorithm.
 * The RSA key pair is read from the <em>api.pem</em> file in the <em>LEISTAND_HOME</em> directory.
 * The <code>AccessKeyConfig</code> creates a 2048 bit RSA key if this file is not present and stores
 * the generated key in the <em>LEITSTAND_HOME/api.pem</em> file.
 * <p>
 * The key ID for API access keys is <em>api-access</em>.
 */
@ApplicationScoped
public class AccessKeyConfig {

	/** Holds the API access key ID. */
	public static final String API_KEY_ID = "api-access";

	private static final Logger LOG = getLogger(AccessKeyConfig.class.getName());
    private static final int API_KEY_SIZE = 2048;
    private static final String API_KEY_PEM_FILE = "api.pem";
    private static final String API_ACCESSKEY_SECRET = "API_SECRET";
        
    @Inject
    private Environment env;
    private JwtService jwtService;
    private JWKSet keySet;
   
    @Deprecated
    private Supplier<MessageAuthenticationCode> apiMac;
    
    @Inject
    @Deprecated
    private LegacyMasterSecret legacy;
    
    protected AccessKeyConfig() {
        // CDI
    }

    /**
     * Creates a new <code>AccessKeyConfig</code>
     * @param env the leitstand environment
     */
    public AccessKeyConfig(Environment env) {
        this.env = env;
        legacy = new LegacyMasterSecret(env);
        legacy.init();
        readAccessKeyConfig();
        readLegacyAccessKeyConfig();
    }
    
    @PostConstruct
    protected void readAccessKeyConfig() {    
        KeyPair keyPair = readApiAccessKeyPair();
        DefaultRsaJwtService service = new DefaultRsaJwtService(keyPair, API_KEY_ID);
        jwtService = service;
        keySet = service.getKeySet();
    }

    private KeyPair readApiAccessKeyPair() {
        if (env.fileExists(API_KEY_PEM_FILE)) {
            return env.loadFile(API_KEY_PEM_FILE, PEM_FILE_PROCESSOR);
        } 
        LOG.info("No API access key pair found. Create a new RSA key pair.");
        KeyPair keyPair = generateRsaKeyPair(API_KEY_SIZE);
        env.storeFile(API_KEY_PEM_FILE, exportKeyPair(keyPair));
        return keyPair;
    }
    
    @Deprecated
    private void readLegacyAccessKeyConfig() {
        String secret64 = getSystemProperty(API_ACCESSKEY_SECRET,"changeit");
        
        
        if(secret64 != null) {
            // Compute apiMac for backward compatibility.
            SecretKeySpec apiHmacKey = new SecretKeySpec(legacyDecodeSecret(secret64).toByteArray(), 
                                                        "HS256");
            this.apiMac = () -> {
                return hmac(apiHmacKey);
            };
        }
    }

    /**
     * Decodes the given API access key. 
     * Call {@link Claims#isExpired()} to test whether the access token is expired.
     * Use {@link AccessKeyValidatorService#isRevoked(io.leitstand.security.auth.jwt.Jwt))}
     * to test whether the access key is revoked.
     * @param token the API access key.
     * @return the JWT claims of the given API access key.
     * @throws AccessDeniedException if the access key is malformed or its signature is invalid. 
     */
    public Claims decodeAccessKey(String token){
        try {
            return jwtService.decode(token);
        } catch (JwtException e) {
            LOG.fine(() -> format("%s: Cannot devode %s access token: %s",
                                  AKY0100E_INVALID_ACCESSKEY.getReasonCode(),
                                  API_KEY_ID, 
                                  e.getMessage()));
            throw new AccessDeniedException(e, AKY0100E_INVALID_ACCESSKEY, API_KEY_ID);
        }
    }

    /**
     * Creates an API access key JSON web token. 
     * @param claims the claims of the API access key.
     * @return the serialized JSON web token
     * @throws AccessKeyConfigException if the access token cannot be created
     */
    String signAccessKey(Claims claims) {
        try {
            return jwtService.encode(claims);
        } catch (JwtException e) {
            LOG.fine(() -> format("%: Cannot sign API access key: %s", 
                                  AKY0103E_CANNOT_SIGN_ACCESSKEY.getReasonCode(),
                                  e.getMessage()));
            throw new AccessKeyConfigException(e, AKY0103E_CANNOT_SIGN_ACCESSKEY);
        }
    }
    
    /**
     * Creates an API access key JSON web token. 
     * @param claims the claims of the API access key.
     * @return the serialized JSON web token
     * @throws AccessKeyConfigException if the access token cannot be created
     */
    public String signApiAccessKey(Builder claims) {
        return signAccessKey(claims.build());
    }
   
    @Deprecated
    public String apiKeyHmac(String key) {
        return getUrlEncoder().encodeToString(apiMac.get().sign(key));
    }
    
    @Deprecated
    private Secret legacyDecodeSecret(String secret) {
        byte[] cipher = getDecoder().decode(secret);
        try {
            return new Secret(legacy.decrypt(cipher));
        } catch (MasterSecretException e) {
            return new Secret(cipher);
        }
    }

	public JWKSet getKeySet() {
		return keySet;
	}


            
}
