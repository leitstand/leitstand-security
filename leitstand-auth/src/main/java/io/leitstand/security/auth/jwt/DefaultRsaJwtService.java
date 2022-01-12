package io.leitstand.security.auth.jwt;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static io.leitstand.commons.model.StringUtil.isEmptyString;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Logger.getLogger;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.logging.Logger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

public class DefaultRsaJwtService implements JwtService {
    
    private static final Logger LOG = getLogger(DefaultRsaJwtService.class.getName());
    
    private static JWSAlgorithm requireRSAAlgorithm(JWSAlgorithm algorithm) {
        if(JWSAlgorithm.Family.RSA.contains(algorithm)) {
            return algorithm;
        } 
        throw new IllegalArgumentException("Please pick an algorithm from "+JWSAlgorithm.Family.RSA);
    }
    
    private static void requireNonEmpty(String keyId) {
        if (isEmptyString(keyId)) {
            throw new IllegalArgumentException("Key-ID must not be empty");
        }
    }


    private JWSAlgorithm algorithm;
    private String kid;
    private RSAKey jwk;
    private RSASSASigner signer;
    private RSASSAVerifier verifier;
    
    public DefaultRsaJwtService(KeyPair keyPair, String keyId) {
        this(RS256,keyPair,keyId);
    }
    
    public DefaultRsaJwtService(JWSAlgorithm algorithm, KeyPair keyPair, String keyId) {
        this.algorithm = requireRSAAlgorithm(algorithm);
        requireNonNull(keyPair, "RSA key pair is mandatory");
        this.kid = requireNonNull(keyId, "Key-ID is mandatory");
        requireNonEmpty(keyId);
        
        jwk = new RSAKey
                  .Builder((RSAPublicKey)keyPair.getPublic())
                  .keyID(keyId)
                  .build();
        
        signer = new RSASSASigner(keyPair.getPrivate());
        try {
            verifier = new RSASSAVerifier(jwk);
        } catch (JOSEException e) {
            String msg = format("Cannot create RSA verifier for %s key: %s", keyId, e.getMessage());
            LOG.severe(msg); 
            throw new JwtException(msg, e);
        }
    }

    @Override
    public String encode(Claims claims) {
        try {
            JWSHeader header = new JWSHeader
                               .Builder(algorithm)
                               .keyID(kid)
                               .build();
            
            SignedJWT jwt = new SignedJWT(header, claims.getClaims());
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            String msg = "Cannot sign "+kid+" JWT token: "+e.getMessage();
            LOG.fine(msg);
            throw new JwtException(msg,e);
        }
    }

    @Override
    public Claims decode(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (verifier.verify(jwt.getHeader(), jwt.getSigningInput(), jwt.getSignature())) {
                return new Claims(jwt.getJWTClaimsSet());
            }
            throw new JwtException("Invalid "+kid+" token signature.");
        } catch (ParseException | JOSEException e) {
            String msg = "Cannot verify "+kid+" JWT token: "+e.getMessage();
            LOG.fine(msg);
            throw new JwtException(msg,e);
        }
    }
    
	@Override
	public Jwt decodeToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSHeader header = jwt.getHeader();
            if (verifier.verify(header, jwt.getSigningInput(), jwt.getSignature())) {
                return new Jwt(header, jwt.getJWTClaimsSet());
            }
            throw new JwtException("Invalid "+kid+" token signature.");
        } catch (ParseException | JOSEException e) {
            String msg = "Cannot verify "+kid+" JWT token: "+e.getMessage();
            LOG.fine(msg);
            throw new JwtException(msg,e);
        }	
    }

	public JWKSet getKeySet() {
		return new JWKSet(jwk);
	}

}
