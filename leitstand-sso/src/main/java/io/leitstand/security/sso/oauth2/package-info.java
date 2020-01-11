/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
/**
 * Contains a <a href="https://tools.ietf.org/html/rfc6749#section-4.1">OAuth Authorization Grant Flow</a> implementation to spawn a Single Sign-On (SSO) domain
 * across the EMS and associated open-source tools.
 * <p>
 * OAuth is a distributed authorization protocol specified in <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 * The idea is to <i>authorize</i> access to a resource describing the <i>authenticated</i> user.
 * By that, other systems can establish a session for the authenticated user.
 * Session establishment itself is not specified by OAuth and therefore done by the respective system in a proprietary fashion.
 * <p>
 * OAuth, as authorization protocol, merely defines how to authorize resource access but does not specify the structure of a resource.
 * For SSO, however, it is key that all systems agreed on the structure of the user resource in order to obtain user data such as the user name as an example.
 * <a href="https://openid.net">OpenID</a> addresses exactly this issue. 
 * It specifies the authentication flow based on OAuth's Authorization Grant Flow and defines data structures to describe an authenticated user.
 * The {@link io.leitstand.security.sso.oidc} package contains an OpenID compliant user resource.
 */
package io.leitstand.security.sso.oauth2;