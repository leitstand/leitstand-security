package io.leitstand.security.rsa;

public class RsaException extends RuntimeException{

    private static final long serialVersionUID = 1L;

    public RsaException(Exception cause) {
        super(cause);
    }
    
    public RsaException(String message) {
        super(message);
    }
    
    public RsaException(String message, Exception cause) {
        super(message, cause);
    }
    
}
