/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth;

import java.security.Principal;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.jsonb.UserIdAdapter;

/**
 * The identifier of an authenticated user.
 */
@JsonbTypeAdapter(UserIdAdapter.class)
public class UserId extends Scalar<String> {

	private static final long serialVersionUID = 1L;

	/**
	 * Alias for the {@link #valueOf(Principal)} method.
	 * <p>
	 * Creates a <code>UserId</code> from the given principal's name.
	 * @param principal the principal name
	 * @return the created <code>UserId</code> or <code>null</code> if the
	 * specified <code>Principal</code> is <code>null</code> or the principal's name is <code>null</code> or empty.
	 */
	public static UserId userId(Principal principal) {
		return valueOf(principal);
	}
	
	/**
	 * Alias for the {@link #valueOf(String)} method.
	 * <p>
	 * Creates a <code>UserId</code> from the specified string.
	 * @param userId the user id.
	 * @return the created <code>UserId</code> instance or 
	 * <code>null</code> if the specified string is <code>null</code> or empty.
	 */
	public static UserId userId(String userId) {
		return valueOf(userId);
	}
	
	/**
	 * Creates a <code>UserId</code> from the specified string.
	 * @param userId the user id.
	 * @return the created <code>UserId</code> instance or 
	 * <code>null</code> if the specified string is <code>null</code> or empty.
	 */
	public static UserId valueOf(String userId) {
		return fromString(userId,UserId::new);
	}
	

	public static UserId valueOf(Principal principal) {
		return principal != null ? valueOf(principal.getName()) : null; 
	}
	
	@NotNull(message="{user_id.required}")
	@Pattern(regexp="\\p{Graph}{2,64}", 
			 message="{user_id.invalid}")
	private String value;
	
	protected UserId() {
		// CDI
	}
	
	/**
	 * Creates a <code>UserId</code>.
	 * @param value the user ID
	 */
	public UserId(String value){
		this.value = value;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getValue() {
		return value;
	}

	/**
	 * Returns the user id length in characters.
	 * @return the suer id length in characters.
	 */
	public int length() {
		return value.length();
	}



}
