package io.leitstand.security.sso.sys.service;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

/**
 * Enumeration of Single-Sign On reason codes.
 */
public enum ReasonCode implements Reason {
    
    /**
     * Access denied due to invalid credentials.
     */
    SYS0001E_INVALID_SYSTEM_CREDENTIALS;
    
    
    private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("SystemMessages");
    
    /**
     * {@inheritDoc}
     */
    public String getMessage(Object... args){
        try{
            String pattern = MESSAGES.getString(name());
            return MessageFormat.format(pattern, args);
        } catch(Exception e){
            return name() + Arrays.asList(args);
        }
    }


    
}
