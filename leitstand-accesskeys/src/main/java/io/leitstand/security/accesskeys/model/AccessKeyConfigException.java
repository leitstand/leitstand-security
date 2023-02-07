package io.leitstand.security.accesskeys.model;

import io.leitstand.commons.LeitstandException;
import io.leitstand.security.accesskeys.service.ReasonCode;

/**
 * The <code>AccessKeyConfigException</code> is raised if an invalid API access key configuration gets detected.
 */
public class AccessKeyConfigException extends LeitstandException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new <code>AccessKeyConfigException</code>.
     * @param reason the reason code why this exception is raised
     * @param arguments the arguments for the reason code status message.
     */
    public AccessKeyConfigException(ReasonCode reason, Object... arguments) {
        super(reason,arguments);
    }

    /**
     * Creates a new <code>AccessKeyConfigException</code>.
     * @param cause the root cause of this exception
     * @param reason the reason why this exception is raised
     * @param arguments the arguments for the reason code status message
     */
    public AccessKeyConfigException(Exception cause, ReasonCode reason, Object... arguments) {
        super(cause,reason,arguments);
    }

}