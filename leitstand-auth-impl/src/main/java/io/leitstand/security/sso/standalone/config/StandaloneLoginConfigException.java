package io.leitstand.security.sso.standalone.config;

import io.leitstand.commons.LeitstandException;
import io.leitstand.security.sso.standalone.ReasonCode;


/**
 * The <code>StandaloneLoginConfigException</code> signals a standalone login configuration issue.
 */
public class StandaloneLoginConfigException extends LeitstandException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new <code>StandaloneLoginConfigException</code>.
     * @param reason the reason why this exception is raised
     * @param args the reason message arguments
     */
    public StandaloneLoginConfigException(ReasonCode reason, Object... args) {
        super(reason, args);
    }
    
    /**
     * Creates a new <code>StandaloneLoginConfigException</code>.
     * @param cause the root cause why this exception is raised
     * @param reason the reason why this exception is raised
     * @param args the reason message arguments
     */
    public StandaloneLoginConfigException(Exception cause, ReasonCode reason, Object... args) {
        super(cause, reason, args);
    }
    
}
