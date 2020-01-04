/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
/**
 * Contains utilities and base classes to create and verify <a href="https://tools.ietf.org/html/rfc7523">RFC 7523 compliant</a> JSON Web Tokens (JWT).
 * <p> 
 * {@link JsonWebToken} is the base class for all EMS JSON Web Token implementations.
 * <h2>Token signature</h2>
 * All tokens are signed using the <code>HMAC-SHA256</code> (HS256) algorithm.
 * The following steps are executed to obtain the secret to sign the token:
 * <ol>
 * <li>Read <code>jwt.secret</code> system property. This property contains a Base64 encoded secret encrypted with the {@link MasterSecret}, if present</li>
 * <li>Read <code>jwt.secret</code> property from <code>/etc/rbms/jwt.properties</code> file, if the file is present. Again, the secret is encrypted with the master secret and Base64 encoded.</li>
 * <li>If neither <code>jwt.secret</code> system property nor <code>jwt.properties</code> file is present, the a hardcoded default secret is used.</li>
 * </ol>
 * <h2>Token expiry</h2>
 * The <code>jwt.ttl</code> property defines the token's time-to-live as time period. 
 * The period consists of a value and a unit, where supported units are 
 * <ul>
 * <li><code>s</code> for seconds</li>
 * <li><code>m</code> for minutes</li>
 * <li><code>h</code> for hours</li>
 * </ul>
 * Similar to <code>jwt.secret</code> the implementation looks first for a <code>jwt.ttl</code> system property and 
 * then for a <code>jwt.ttl</code> property in the <code>/etc/rbms/jwt.properties</code> file. 
 * The time-to-live defaults to one hour (<code>1h</code>) if unspecified.
 * <p>
 * The <code>jwt.refresh</code> property defines the time period prior to token expiry, 
 * where the server is allowed to refresh the token by issuing a new token.
 * If not specified, the value is 5% of the token's time-to-live. 
 * If time-to-live is a hour, then the token gets refreshed if a request occurred 3 minutes prior to the token expiration.
 * The expiration date of the new token is the expiration date of the expired token plus the configured time-to-live.
 */
package io.leitstand.security.auth.jwt;
