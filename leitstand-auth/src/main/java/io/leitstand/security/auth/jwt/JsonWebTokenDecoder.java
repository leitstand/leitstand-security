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
package io.leitstand.security.auth.jwt;

import static io.leitstand.security.auth.jwt.Json.unmarshal;
import static java.util.Base64.getDecoder;
import static java.util.logging.Level.FINER;

import java.lang.reflect.Constructor;
import java.util.Base64.Decoder;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;


/**
 * A stateless, thread-safe service to decode JSON web tokens.
 * <p>
 * Decoding a JSON Web Token (JWT) consists of four steps.
 * <ol>
 * <li>Split the token into three parts: header, payload and signature.</li>
 * <li>Validate the token signature</li>
 * <li>Provided that the signature is valid, decode header and payload</li>
 * <li>Parse JSON to restore header and payload java objects</li>.
 * </ol>
 * 
 * @see JsonWebToken <code>JsonWebToken</code>, the base class for JSON Web tokens.
 * @see JsonWebTokenEncoder JsonWebTokenEncoder, the <code>JsonWebToken</code> encoder.
 */
@ApplicationScoped
public class JsonWebTokenDecoder {
	
	private static final Logger LOG = Logger.getLogger(JsonWebTokenDecoder.class.getName());
	
	private JwtSignatureService signer;
	
	/**
	 * No-argument constructor to support JsonWebTokenDecoder proxying.
	 */
	protected JsonWebTokenDecoder() {
		// CDI constructor
	}
	
	/**
	 * Creates a <code>JsonWebTokenDecoder</code>.
	 * @param service - the signature service to validate the token's signature
	 */
	@Inject
	public JsonWebTokenDecoder(JwtSignatureService service) {
		this.signer = service;
	}

	/**
	 * Decodes a JSON web token.
	 * @param tokenType - the <code>JsonWebToken</code> implementation type
	 * @param payloadType - the payload type
	 * @param token - the encoded JSON web token.
	 * @return the <code>JsonWebToken</code> instance
	 * @throws JsonWebTokenSignatureException if the signature is invalid or HS256 is not used as signature algorithm
	 */
	public <T extends JsonWebToken<?>,P> T decode(Class<T> tokenType, Class<P> payloadType, String token) {
		String[] parts = token.split("\\.");
		
		Decoder base64 = getDecoder();
		String  head64 = parts[0];
		String  load64 = parts[1];	
		String  hash64 = parts[2];
		
		JsonWebToken.Header header = unmarshal(JsonWebToken.Header.class,
											   base64.decode(head64));
		assertHS256(header.getAlgorithm());
			
		boolean valid  = signer.isValidSignature(hash64, head64, load64);
		if(valid) {
			try {
				P payload = unmarshal(payloadType, 
									  base64.decode(load64));
				Constructor<T> ctor = tokenType.getDeclaredConstructor(payloadType);
				ctor.setAccessible(true);
				return ctor.newInstance(payload);
			} catch (Exception e) {
				LOG.fine(() -> "Cannot instantiate valid JWT: "+e.getMessage());
				LOG.log(FINER, e.getMessage(), e);
				throw new IllegalStateException(e);
			}
		}
		
		throw new JsonWebTokenSignatureException("Signature mismatch");
	}

	private void assertHS256(String algorithmn) {
		if("HS256".equals(algorithmn)) {
			return;
		}
		throw new JsonWebTokenSignatureException("Unsupported algorithmn "+algorithmn);
	}
	
}
