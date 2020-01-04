/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import static io.leitstand.commons.db.DatabaseService.prepare;
import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.security.auth.Role.ADMINISTRATOR;
import static io.leitstand.security.users.model.PasswordService.ITERATIONS;
import static io.leitstand.security.users.model.Role.findRoleByName;
import static io.leitstand.security.users.model.User.findUserByUserId;
import static io.leitstand.security.users.model.User.findUserByUuid;
import static io.leitstand.security.users.service.ReasonCode.IDM0001I_USER_STORED;
import static io.leitstand.security.users.service.ReasonCode.IDM0002I_PASSWORD_RESET;
import static io.leitstand.security.users.service.ReasonCode.IDM0003I_PASSWORD_UPDATED;
import static io.leitstand.security.users.service.ReasonCode.IDM0004E_USER_NOT_FOUND;
import static io.leitstand.security.users.service.ReasonCode.IDM0005E_INCORRECT_PASSWORD;
import static io.leitstand.security.users.service.ReasonCode.IDM0006E_ROLE_NOT_FOUND;
import static io.leitstand.security.users.service.ReasonCode.IDM0007E_ADMIN_PRIVILEGES_REQUIRED;
import static io.leitstand.security.users.service.ReasonCode.IDM0008E_PASSWORD_MISMATCH;
import static io.leitstand.security.users.service.ReasonCode.IDM0009I_USER_REMOVED;
import static io.leitstand.security.users.service.UserReference.newUserReference;
import static io.leitstand.security.users.service.UserSettings.newUserSettings;
import static java.lang.String.format;
import static java.util.logging.Level.FINER;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.security.enterprise.credential.Password;
import javax.servlet.http.HttpServletRequest;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.auth.Authenticated;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.users.service.EmailAddress;
import io.leitstand.security.users.service.UserReference;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;
import io.leitstand.security.users.service.UserSubmission;

/**
 * Stateless, transactional, default {@link UserService} implementation.
 */
@Service
public class DefaultUserService implements UserService {

	private static final Logger LOG = Logger.getLogger(DefaultUserService.class.getName());
	
	@Inject
	@IdentityManagement
	private Repository repository;
	
	@Inject
	@IdentityManagement
	private DatabaseService db;
	
	@Inject
	private Messages messages;
	
	@Inject 
	private PasswordService hashing;
	
	@Inject
	private HttpServletRequest context;
	
	public DefaultUserService() {
		// CDI constructor
	}

	protected DefaultUserService(Repository repository,
								 DatabaseService db,
								 PasswordService hashing,
								 Messages messages,
								 HttpServletRequest context) {
		this.repository = repository;
		this.db = db;
		this.messages = messages;
		this.hashing = hashing;
		this.context = context;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<UserReference> findUsers(String filter) {
		
		if(filter == null || filter.isEmpty()) {
			return db.executeQuery(prepare("SELECT uuid, userid, email, givenname, surname FROM auth.userdata ORDER BY surname,givenname,userid"), 
						    	   rs -> newUserReference()
						    	   		 .withUuid(rs.getString(1))
						    	   		 .withUserId(UserId.valueOf(rs.getString(2)))
						    	   		 .withEmailAddress(EmailAddress.valueOf(rs.getString(3)))
						    	   		 .withGivenName(rs.getString(4))
						    	   		 .withSurname(rs.getString(5))
						    	   		 .build());
		}

		return db.executeQuery(prepare("SELECT uuid, userid, email, givenname, surname FROM auth.userdata WHERE (SURNAME ~ ? OR USERID ~ ? ) ORDER BY surname,givenname,userid",
									   filter,
									   filter), 
					    	   rs -> newUserReference()
					    	   		 .withUuid(rs.getString(1))
					    	   		 .withUserId(UserId.valueOf(rs.getString(2)))
					    	   		 .withEmailAddress(EmailAddress.valueOf(rs.getString(3)))
					    	   		 .withGivenName(rs.getString(4))
					    	   		 .withSurname(rs.getString(5))
					    	   		 .build());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void storeUserSettings(UserSettings settings) {
		User user = findUser(settings.getUuid());
		if(context.isUserInRole(ADMINISTRATOR) || user.getUserId().equals(UserId.valueOf(context.getUserPrincipal()))) {
			user.setUserId(settings.getUserId());
			user.setGivenName(settings.getGivenName());
			user.setSurname(settings.getSurname());
			user.setEmailAddress(settings.getEmail());
			if(settings.isCustomAccessTokenTtl()) {
				user.setAccessTokenTtl(settings.getAccessTokenTtl(),
									   settings.getAccessTokenTtlUnit());
			} else {
				user.setAccessTokenTtl(0, null);
			}
			if(context.isUserInRole(ADMINISTRATOR)) {
				List<Role> roles = loadRoles(settings.getRoles());
				user.setRoles(roles);
			}
			messages.add(createMessage(IDM0001I_USER_STORED, 
									   settings.getUserId()));
			return;
			
		}
		throw new AccessDeniedException(IDM0007E_ADMIN_PRIVILEGES_REQUIRED, 
										user.getUserId());

	}

	private User findUser(String uuid) {
		User user = repository.execute(findUserByUuid(uuid));
		if(user == null) {
			throw new EntityNotFoundException(IDM0004E_USER_NOT_FOUND, 
											  uuid);
		}
		return user;
	}

	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UserSettings getUser(UserId userId) {
		User user = findUser(userId);
		return settingsOf(user);
	}
	
	@Override
	public UserSettings getUser(String uuid) {
		User user = findUser(uuid);
		return settingsOf(user);
	}

	private UserSettings settingsOf(User user) {
		return newUserSettings()
			   .withUserId(user.getUserId())
			   .withUuid(user.getUuid())
			   .withEmailAddress(user.getEmailAddress())
			   .withGivenName(user.getGivenName())
			   .withSurname(user.getSurname())
			   .withDateCreated(user.getDateCreated())
			   .withDateModified(user.getDateModified())
			   .withRoles(user.getRoles(Role::getName))
			   .withAccessTokenTtl(user.getTokenTtl(),user.getTokenTtlUnit())
			   .build();
	}

	
	/**
	 * Searches the user by the specified ID and throws an <code>EntityNotFoundException</code>
	 * if the user does not exist.
	 * @param userId - the user ID
	 * @return the user with the specified user ID
	 * @throws EntityNotFoundException if the user does not exist.
	 */
	protected User findUser(UserId userId) {
		User user = repository.execute(findUserByUserId(userId));
		if(user == null) {
			LOG.fine(()->format("%s: User %s does not exist.",
								IDM0004E_USER_NOT_FOUND.getReasonCode(),
								userId));
			throw new EntityNotFoundException(IDM0004E_USER_NOT_FOUND, 
											  userId);
		}
		return user;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setPassword(UserId userId, 
							Password current, 
							Password newpass,
							Password confirm) {
		User user = findUser(userId);
		setPassword(user, 
					current, 
					newpass, 
					confirm);
		
	}
	
	@Override
	public void setPassword(String uuid, 
							Password currentPassword,
							Password newPassword, 
							Password confirmPassword) {
		User user = findUser(uuid);
		setPassword(user,
					currentPassword,
					newPassword,
					confirmPassword);
	}	


	private void setPassword(User user, 
							 Password currentPassword, 
							 Password newPassword, 
							 Password confirmPassword) {
		if(hashing.isExpectedPassword(currentPassword, 
									  user.getSalt(), 
									  user.getPasswordHash(), 
									  user.getIterations())) {

			if(isDifferent(newPassword,confirmPassword)) {
				LOG.fine(() -> format("%s: Cannot change password for user %s because of password confirmation mismatch.",
									  IDM0008E_PASSWORD_MISMATCH.getReasonCode(),
									  user.getUserId()));
				throw new UnprocessableEntityException(IDM0008E_PASSWORD_MISMATCH);
			}

			
			// Compute salt for new password hash
			byte[] salt = hashing.salt();
			byte[] hash = hashing.hash(newPassword, 
									   salt, 
									   ITERATIONS);
			user.setPassword(hash, 
							 salt, 
							 ITERATIONS);
			messages.add(createMessage(IDM0003I_PASSWORD_UPDATED,
									   user.getUserId()));
			return;
		}
		
		LOG.fine(() -> format("%s: Password change for user %s rejected due to incorrect password.",
							 IDM0005E_INCORRECT_PASSWORD.getReasonCode(),
							 user.getUserId()));
		throw new UnprocessableEntityException(IDM0005E_INCORRECT_PASSWORD);
	}

	private static boolean isDifferent(Password newpass, Password confirm) {
		if(Arrays.equals(newpass.getValue(), confirm.getValue())){
			confirm.clear();
			return false;
		} 
		newpass.clear();
		confirm.clear();
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void resetPassword(UserId userId, 
							  Password newPassword, 
							  Password confirmPassword) {
		User user = findUser(userId);
		resetPassword(user, 
					  newPassword, 
					  confirmPassword);
	}
	
	@Override
	public void resetPassword(String uuid, 
							  Password newPassword, 
							  Password confirmPassword) {
		User user = findUser(uuid);
		resetPassword(user,
					  newPassword,
					  confirmPassword);
	}

	private void resetPassword(User user, 
							   Password newPassword, 
							   Password confirmPassword) {
		if(isDifferent(newPassword, confirmPassword)) {
			LOG.fine(() -> format("%s: Cannot reset password because of invalid password confirmation.",
								  IDM0008E_PASSWORD_MISMATCH.getReasonCode()));
			throw new UnprocessableEntityException(IDM0008E_PASSWORD_MISMATCH, 
												   context);
		}
		byte[] salt    = hashing.salt();
		byte[] hash    = hashing.hash(newPassword, 
									  salt, 
									  ITERATIONS);
		user.setPassword(hash, 
						 salt, 
						 ITERATIONS);
		LOG.info(() -> format("%s - Password reset for %s",
				IDM0002I_PASSWORD_RESET.getReasonCode(),
				user.getUserId()));
		messages.add(createMessage(IDM0002I_PASSWORD_RESET,
								   user.getUserId()));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isValidPassword(UserId userId, Password password) {
		try {
			User user = findUser(userId);
			boolean valid = hashing.isExpectedPassword(password, 
													   user.getSalt(), 
											  		   user.getPasswordHash(),
											  		   user.getIterations());
			if(valid) {
				LOG.finer(() -> format("Valid password verified for user %s",userId));
			} else {
				LOG.finer(() -> format("Invalid password for user %s detected",userId));
			}
			return valid;
		} catch (EntityNotFoundException e) {
			LOG.fine(() -> e.getMessage());
			LOG.log(FINER,
					e.getMessage(),
					e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeUser(UserId userId) {
		User user = findUser(userId);
		if(user != null) {
			removeUser(user);
		}
	}

	@Override
	public void addUser(UserSubmission submission) {
		Password newpass = submission.getPassword();
		Password confirm = submission.getConfirmedPassword();
		if(isDifferent(newpass,confirm)) {
			messages.add(createMessage(IDM0008E_PASSWORD_MISMATCH));
			return;
		}
		
		User user = new User(submission.getUuid(),
							 submission.getUserId());
		user.setGivenName(submission.getGivenName());
		user.setSurname(submission.getSurname());
		user.setEmailAddress(submission.getEmail());
		if(submission.isCustomAccessTokenTtl()) {
			user.setAccessTokenTtl(submission.getAccessTokenTtl(), 
								   submission.getAccessTokenTtlUnit());
		} else {
			user.setAccessTokenTtl(0, null);
		}
		List<Role> roles = loadRoles(submission.getRoles());
		user.setRoles(roles);
		
		byte[] salt = hashing.salt();
		byte[] hash = hashing.hash(submission.getPassword(), 
								   salt, 
								   ITERATIONS);
		user.setPassword(hash, 
						 salt, 
						 ITERATIONS);
		repository.add(user);
		LOG.info(()->format("%s: User %s created.",
							IDM0001I_USER_STORED.getReasonCode(),
							user.getUserId()));
		messages.add(createMessage(IDM0001I_USER_STORED, user.getUserId()));
	}

	private List<Role> loadRoles(Collection<String> roleNames) {
		List<Role> roles = new LinkedList<>();
		for(String roleName : roleNames) {
			Role role = repository.execute(findRoleByName(roleName));
			if(role == null) {
				throw new EntityNotFoundException(IDM0006E_ROLE_NOT_FOUND,
												  roleName);
			}
			roles.add(role);
		}
		return roles;
	}

	@Override
	@Produces
	@RequestScoped
	@Authenticated
	public UserSettings getAuthenticatedUser() {
		UserId userId = UserId.valueOf(context.getUserPrincipal());
		LOG.fine(()->format("Return authenticated user %s",userId));
		return getUser(userId);
	}

	@Override
	public void removeUser(String uuid) {
		User user = repository.execute(findUserByUuid(uuid));
		if(user != null) {
			removeUser(user);
		}
	}

	private void removeUser(User user) {
		repository.remove(user);
		LOG.fine(()->format("%s: Removed user %s (%s).", 
							IDM0009I_USER_REMOVED.getReasonCode(),
							user.getUserId(),
							user.getUuid()));
		messages.add(createMessage(IDM0009I_USER_REMOVED,
								   user.getUserId(),
								   user.getUuid()));
	}

}
