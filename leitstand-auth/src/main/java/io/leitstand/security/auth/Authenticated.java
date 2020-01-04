/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

/**
 * Qualified annotation to obtain information of the authenticated user.
 * Use <code>{@literal @Inject} {@literal @Authenticated} UserId</code> 
 * to get the {@link UserId} of the authenticated user 
 * to obtain the settings of the authenticated user.
 * @see UserId
 * 
 */
@Retention(RUNTIME)
@Target({METHOD, PARAMETER, FIELD, TYPE})
@Inherited
@Qualifier
public @interface Authenticated {

}
