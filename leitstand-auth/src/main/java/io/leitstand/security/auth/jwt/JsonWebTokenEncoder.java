/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jwt;

import static io.leitstand.security.auth.jwt.Json.marshal;
import static java.util.Base64.getEncoder;

import java.util.Base64.Encoder;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * A stateless, thread-safe service to encode JSON Web Tokens.
 * <p>
 * The encoding process consists of five steps:
 * <ol>
 * 	<li>Convert the JSON Web Token (JWT) header to a Base64 encoded JSON string.</li>
 *  <li>Convert the JWT payload to a Base64 encoded JSON string.</li>
 *  <li>Concatenate header and payload strings from the two previous steps using a dot (.) as delimiter.</code>
 *  <li>Compute the token signature</li>
 *  <li>Append the Base64 encoded signature to header and payload using a dot (.) as delimiter again. 
 * </ol>
 * The listing below outlines the process in pseude-code:
 * <pre>
 *  head64 = base64(json(jwt.getHeader())
 *  load64 = base64(json(jwt.getPayload())
 *  sign64 = base64(hs256(head64+"."+load64,secret))
 *  jwt = head64+"."+load64+"."+sign64
 * </pre>
 * </p>
 * @see JsonWebToken <code>JsonWebToken</code>, the JSON Web Token base class
 * @see JsonWebTokenDecoder <code>JsonWebTokenDecoder</code>, JSON Web Token decoder.
 */
@ApplicationScoped
public class JsonWebTokenEncoder {
	
	
	private JwtSignatureService signer;
	
	/**
	 * No-argument constructor to support JsonWebTokenDecoder proxying.
	 */
	protected JsonWebTokenEncoder() {
		// CDI constructor
	}
	
	/**
	 * Creates a <code>JsonWebTokenEncoder</code>.
	 * @param service the service to compute the token signature
	 */
	@Inject
	public JsonWebTokenEncoder(JwtSignatureService service) {
		this.signer = service;
	}
	
	public String encode(JsonWebToken<?> token) {
		Encoder base64 = getEncoder();
		String  head64 = base64.encodeToString(marshal(token.getHeader()));
		String  load64 = base64.encodeToString(marshal(token.getPayload()));	
		String  hash64 = signer.sign64(head64,load64);	
		return head64+"."+load64+"."+hash64;
	}
	
}
