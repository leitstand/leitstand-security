package io.leitstand.security.auth;

import static io.leitstand.commons.model.Patterns.UUID_PATTERN;

import java.util.UUID;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.jsonb.UserIdAdapter;

/**
 * Immutable unique user account ID in UUIDv4 format.
 */
@JsonbTypeAdapter(UserIdAdapter.class)
public class UserId extends Scalar<String>{

	private static final long serialVersionUID = 1L;

	/**
	 * Creates a random user account ID.
	 * @return a random user account ID.
	 */
	public static final UserId randomUserId() {
		return valueOf(UUID.randomUUID().toString());
	}
	
	/**
	 * Alias of the {@link #valueOf(String)} factory method.
	 * <p>
	 * Converts the specified string to a <xcode>UserId</code>
	 * @param userId the user account ID
	 * @return the translated <code>UserId</code> or <code>null</code> if the specified string was <code>null</code> or an empty string
	 */
	public static final UserId userId(String userId) {
		return valueOf(userId);
	}
	
	/**
	 * Converts the specified string to a <xcode>UserId</code>
	 * @param userId the user account ID
	 * @return the translated <code>UserId</code> or <code>null</code> if the specified string was <code>null</code> or an empty string
	 */
	public static final UserId valueOf(String userId) {
		return fromString(userId,UserId::new);
	}
	
	@NotNull(message="{user_id.required}")
	@Pattern(regexp=UUID_PATTERN, message="{user_id.invalid}")
	private String value;
	
	/**
	 * Creates a <code>UserId</code>
 	 * @param userId the user account ID
	 */
	public UserId(String userId) {
		this.value = userId;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getValue() {
		return value;
	}
	
	
}
