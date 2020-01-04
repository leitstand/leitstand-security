/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
/**
 * Contains the login audit log data model and service implementations.
 * <p>
 * All log records are written to a database.
 * The secret to sign all log records is read from the <code>login.record.secret</code> property.
 * This property is either specified as system property or read from the <code>/etc/rbms/login-audit-log.properties</code> file,
 * with system property having a precedence over the config file.
 * The property value is Base64 encoded and encrypted with the {@link MasterSecret}.
 */
package io.leitstand.security.login.log.model;
