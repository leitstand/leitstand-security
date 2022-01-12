package io.leitstand.security.auth.jwt;

/**
 * A <code>JwtException</code> is thrown when a JWT is invalid by either being malformed or having an invalid signature.
 * Expired JWTs do not cause an exception to be thrown. Use {@link Claims#isExpired()} to test whether a JWT is expired or not.
 */
public class JwtException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a <code>JwtException</code>.
     * @param message the message text
     */
    public JwtException(String message) {
        super(message);
    }

    /**
     * Creates a <code>JwtException</code>.
     * @param cause the root cause
     */
    public JwtException(Exception cause) {
        super(cause);
    }
    

    /**
     * Creates a <code>JwtException</code>.
     * @param message the message text
     * @param cause the root cause
     */
    public JwtException(String message, Exception cause) {
        super(message, cause);
    }
    
}
