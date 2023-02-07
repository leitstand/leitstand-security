package io.leitstand.security.sso.standalone.oauth2;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.crypto.SecureHashes.sha256;
import static io.leitstand.security.crypto.SecureRandomFactory.newSHA1PRNG;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmacSha256;
import static java.lang.Character.MAX_RADIX;
import static java.lang.System.currentTimeMillis;
import static java.nio.ByteBuffer.allocate;
import static java.util.Arrays.mismatch;
import static java.util.UUID.randomUUID;
import static java.util.logging.Logger.getLogger;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

import io.leitstand.security.crypto.Secret;

/**
 * The <code>CodeService</code> produces and decodes codes to authorize a client to obtain an access token 
 * to read the user information of the authenticated user. The client uses the code in combination with client 
 * credentials to obtain an access code.
 */
@ApplicationScoped
class CodeService {
	
	private static final Logger LOG = getLogger(CodeService.class.getName());
	
	
	private SecureRandom random;
	
	private Secret secret;
	
	
	@PostConstruct
	protected void initPRNG() {
		random = newSHA1PRNG();
		secret = new Secret(sha256().hash(getSystemProperty("LEITSTAND_CODE_SECRET", randomUUID().toString())));
	}
	
	/**
	 * Creates an access code for the given client ID. The code expires within 60 seconds.
	 * @param clientId the client ID
	 * @return a code to obtain an access token for the given client ID
	 */
	String createCode(String clientId, String userName) {
		long exp = currentTimeMillis() + 60000;
		long salt = random.nextLong();
		byte[] clientIdBytes = toUtf8Bytes(clientId);
		byte[] userNameBytes = toUtf8Bytes(userName);
		
		//   8 bytes for the system time
		// + 8 bytes for the noise
		// + 1 byte for the client ID length
		// + 1 byte for the user name length
		// = 18 bytes + client ID bytes + user name bytes
		ByteBuffer payloadBuffer = allocate(18+clientIdBytes.length+userNameBytes.length); 
		payloadBuffer.put(Integer.valueOf(clientIdBytes.length).byteValue());
		payloadBuffer.put(clientIdBytes);
		payloadBuffer.put(Integer.valueOf(userNameBytes.length).byteValue());
		payloadBuffer.put(userNameBytes);
		payloadBuffer.putLong(exp);
		payloadBuffer.putLong(salt);
		
		byte[] payload = payloadBuffer.array();
		byte[] signature = hmacSha256(secret).sign(payload);
		ByteBuffer code = allocate(payload.length+signature.length);
		code.put(payload);
		code.put(signature);
		return new BigInteger(code.array()).toString(MAX_RADIX);
	}
	
	CodePayload decodeCode(String encodedCode) {
		try {
			ByteBuffer buffer = ByteBuffer.wrap(new BigInteger(encodedCode, MAX_RADIX ).toByteArray());
			byte[] clientIdBytes = new byte[ buffer.get()];
			buffer.get(clientIdBytes);
			String clientId = fromUtf8Bytes(clientIdBytes);
			byte[] userNameBytes = new byte[buffer.get()];
			buffer.get(userNameBytes);
			String userName = fromUtf8Bytes(userNameBytes);
			
			long exp = buffer.getLong();
			if (exp < currentTimeMillis()) {
				LOG.info("Reject SSO access token request from "+clientId+" because code parameter is expired.");
				// Token is expired
				return null;
			}
			
			// Validate token
			buffer.position(0);
			byte[] payload = new byte[18+clientIdBytes.length+userNameBytes.length];
			buffer.get(payload);
			byte[] signature = new byte[32];
			buffer.get(signature, 0, 32);
			if (mismatch(signature, hmacSha256(secret).sign(payload)) > 0) {
				LOG.info("Reject SSO access token request from "+clientId+" because code parameter is invalid.");
				return null;
			}
			return new CodePayload(clientId, userName);
		} catch(Exception e) {
			LOG.fine(() -> "Rejected SSO access token request due to unexepcted error "+e);
			return null;
		}
	}	
	
}
