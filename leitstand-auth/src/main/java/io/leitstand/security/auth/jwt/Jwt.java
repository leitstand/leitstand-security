package io.leitstand.security.auth.jwt;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;

public class Jwt {

	private Claims claims;
	private String algorithm;
	private String keyID;
	
	protected Jwt(JWSHeader header, JWTClaimsSet claims) {
		this.claims = new Claims(claims);
		this.algorithm = header.getAlgorithm().getName();
		this.keyID = header.getKeyID();
	}
	
	
	public Claims getClaims() {
		return claims;
	}
	
	public String getKeyID() {
		return keyID;
	}
	
	public String getAlgorithm() {
		return algorithm;
	}
	
	public boolean isExpired() {
		return claims.isExpired();
	}
}
