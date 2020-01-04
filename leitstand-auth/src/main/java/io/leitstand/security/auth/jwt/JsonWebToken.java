/*
 * (c) RtBrick, Inc All rights reserved, 2015 2019
 */
package io.leitstand.security.auth.jwt;

import static java.lang.System.currentTimeMillis;

import java.time.Duration;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.json.bind.annotation.JsonbProperty;

import io.leitstand.commons.model.ValueObject;

/**
 * Base class for <a href="https://tools.ietf.org/html/rfc7523">RFC 7523</a> compliant JSON Web Tokens.
 * <p>
 * All implementations derived from <code>JsonWebToken</code> use <code>HMAC-SHA256</code> (HS256) to 
 * sign the web token and <code>application/json</code> as token payload content type. 
 * Thus the payload must be hierarchically structured and convertible to JSON.
 * </p>
 * @param <T> the type of payload shipped with the web token.
 */
public abstract class JsonWebToken<T> extends ValueObject {

	/**
	 * The JSON Web Token (JWT) header as specified in the {@link JsonWebToken} class description.
	 * <code><pre>
	 * { "alg" : "HS256",
	 *   "cty" : "application/json",
	 *   "typ" : "JWT"}
	 * </pre></code>
	 */
	public static class Header extends ValueObject{

		@JsonbProperty("alg")
		private String algorithm = "HS256";
		
		@JsonbProperty("cty")
		private String contentType = "application/json";
		
		private String typ = "JWT"; 
		
		/**
		 * Returns the token typ.
		 * @return JWT as token typ
		 */
		public String getTyp() {
			return typ;
		}
		
		/**
		 * Returns the token payload content type, which is <code>application/json</code>.
		 * @return <code>application/json</code>
		 */
		public String getContentType(){
			return contentType;
		}
		
		/**
		 * Returns the algorithm to sign the token, which is HMAC-SHA256 (HS256)
		 * @return HS256
		 */
		public String getAlgorithm() {
			return algorithm;
		}
	}
	
	private Header header;
	private T payload;
	
	/**
	 * Creates a <code>JsonWebToken</code>.
	 * @param payload the token payload
	 */
	public JsonWebToken(T payload) {
		this.header = new Header();
		this.payload = payload;
	}
	
	/**
	 * Returns the JSON web token header.
	 * @return the JSON web token header.
	 */
	public Header getHeader() {
		return header;
	}
	
	/**
	 * Returns the JSON web token payload.
	 * @return the JSON web token payload.
	 */
	public T getPayload() {
		return payload;
	}

	/**
	 * Computes whether the access token exceeds the specified age.
	 * @param duration the amount of time
	 * @param unit the time unit
	 * @return <code>true</code> if the access token exceeds the age, <code>false</code> otherwise.
	 */
	public boolean isOlderThan(long duration, TimeUnit unit) {
		return getDateCreated().getTime() + unit.toMillis(duration) < currentTimeMillis();
	}

	/**
	 * Returns whether this token is expired.
	 * @return <code>true</code> if this token is expired, <code>false</code> otherwise.
	 */
	public boolean isExpired() {
		Date expiry = getDateExpiry();
		return expiry != null && expiry.getTime() < currentTimeMillis();
	}
	
	/**
	 * Computes whether the token will expire within the given duration.
	 * @param duration the amount of time
	 * @param unit the time unit
	 * @return <code>true</code> if the token will expire in the specified time frame
	 */
	public boolean isExpiringWithin(Duration refresh) {
		Date expiry = getDateExpiry();
		return expiry != null && expiry.getTime() < currentTimeMillis() + refresh.toMillis();
	}
	
	/**
	 * Computes whether the token will expire within the given duration.
	 * @param duration the amount of time
	 * @param unit the time unit
	 * @return <code>true</code> if the token will expire in the specified time frame
	 */
	public boolean isExpiringWithin(long duration, TimeUnit unit) {
		Date expiry = getDateExpiry();
		return expiry != null && expiry.getTime() < currentTimeMillis() + unit.toMillis(duration);
	}
	
	/**
	 * Computes whether the access token exceeds the specified age.
	 * @param duration the time to live duration
	 * @return <code>true</code> if the access token exceeds the age, <code>false</code> otherwise.
	 */
	public boolean hasAge(Duration duration) {
		return getDateCreated().getTime() + duration.toMillis() < currentTimeMillis();
	}
	
	/**
	 * Returns the creation date of this JSON Web Token.
	 * @return the JSON Web Token creation date.
	 */
	public abstract Date getDateCreated();
	
	/**
	 * Returns the expiration date of this JSON Web Token or <code>null</code> if no 
	 * expiration date exists
	 * @return the JSON Web Token expiration date.
	 */
	public Date getDateExpiry() {
		return null;
	}
	
}