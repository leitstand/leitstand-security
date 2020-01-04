/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.login.log.model;

import static io.leitstand.commons.db.DatabaseService.prepare;
import static io.leitstand.commons.etc.FileProcessor.properties;
import static io.leitstand.commons.model.ByteArrayUtil.decodeBase64String;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.login.log.model.UserLoginRecord.fetchLastRecord;
import static io.leitstand.security.login.log.service.ReasonCode.AUT0001E_RECORD_NOT_FOUND;
import static io.leitstand.security.login.log.service.UserLoginAuditLogRecordData.newUserLoginRecordData;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmacSha256;
import static java.lang.String.format;
import static java.lang.System.getProperty;
import static java.net.InetAddress.getLocalHost;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;
import static java.util.logging.Level.FINE;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.inject.Inject;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.etc.Environment;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.crypto.MasterSecret;
import io.leitstand.security.crypto.Secret;
import io.leitstand.security.login.log.service.UserLoginAuditLogQuery;
import io.leitstand.security.login.log.service.UserLoginAuditLogRecordData;
import io.leitstand.security.login.log.service.UserLoginAuditLogService;
import io.leitstand.security.login.log.service.UserLoginState;

/**
 * The stateless transactional {@link UserLoginAuditLogService} default implementation.
 * <p>
 * All log records are written to a database.
 * The secret to sign all log records is read from the <code>login.record.secret</code> property.
 * This property is either specified as system property or read from the <code>/etc/rbms/login-audit-log.properties</code> file,
 * with system property having a precedence over the config file.
 * The property value is Base64 encoded and encrypted with the {@link MasterSecret}.
 */
@Service
public class DefaultUserLoginAuditLogService implements UserLoginAuditLogService {

	private static final Logger LOG = Logger.getLogger(DefaultUserLoginAuditLogService.class.getName());
	private static final String AUDIT_PROPERTIES = "audit.properties";
	private static final String EMS_PROPERTY_LOG_RECORD_SECRET = "login.record.secret";
	private String localIp;
	private Secret secret;
	
	@Inject
	@Login
	private Repository audit;
	
	@Inject
	private Environment env;
	
	@Inject
	private MasterSecret master;
	
	@Inject
	@Login
	private DatabaseService db;
	
	/**
	 * Determines the IP address of the host that runs this service and
	 * reads the secret to sign all created login records.
	 */
	@PostConstruct
	protected void readLocalIpAddress() {
		try {
			localIp = getLocalHost().getHostAddress();
		} catch(IOException e) {
			// If a JVM is not able to determine the local IP-Address, we have an urgent issue.
			// This should never happen, but if it happens, we have a trace record and convert the IOException
			// to an unchecked IOException in order to get notified about the problem!
			LOG.log(FINE,e,()->"Cannot determine local IP address to due IO error: "+e.getMessage());
			throw new UncheckedIOException(e);
		}
		Properties auditLogConfig = env.loadFile(AUDIT_PROPERTIES, 
												 properties());
		String secret64 = getProperty(EMS_PROPERTY_LOG_RECORD_SECRET,
									  auditLogConfig.getProperty(EMS_PROPERTY_LOG_RECORD_SECRET));
		if(isNonEmptyString(secret64)) {
			secret = new Secret(master.decrypt(getDecoder().decode(secret64)));
		} else {
			secret = new Secret(toUtf8Bytes("lab-environment-login-audit-log"));
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void log(String remoteIp, String userAgent, UserId userId, UserLoginState loginState) {
		UserLoginRecord previous = audit.execute(fetchLastRecord(localIp));	
		Date loginDate = new Date();
		long id = previous != null ? previous.getId()+1 : 1;
		String rawMessage  = rawMessage(localIp, 
										id, 
										remoteIp, 
										userAgent, 
										userId, 
										loginState,
										previous, 
										loginDate);
		
		String signature   = getEncoder().encodeToString(hmacSha256(secret).sign(rawMessage));
		
		
		UserLoginRecord record = new UserLoginRecord(id,
													 previous,
												 	 localIp,
													 remoteIp,
													 userId,
													 userAgent,
													 loginDate,
													 loginState,
													 signature);
		audit.add(record);
	}

	private static String rawMessage(String localIp,
							  		 long id,
							  		 String remoteIp, 
							  		 String userAgent, 
							  		 UserId userId, 
							  		 UserLoginState loginState,
							  		 UserLoginRecord previous, 
							  		 Date loginDate) {
		return rawMessage(localIp,
						  id,
						  remoteIp, 
						  userAgent, 
						  userId.toString(), 
						  loginState.name(), 
						  previous != null ? previous.getId() : 0L, 
						  loginDate.getTime());
	}
	
	private static String rawMessage(String localIp,
							  		 long   id,
							  		 String remoteIp, 
							  		 String userAgent, 
							  		 String userId, 
							  		 String loginState,
							  		 long   previous, 
							  		 long   loginDate) {
		return format("%s:%d:%s:%s:%s:%s:%d:%d",
					  localIp,
					  id,
					  remoteIp,
					  userAgent,
					  userId,
					  loginState,
					  loginDate,
					  previous);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UserLoginAuditLogRecordData getUserLoginRecord(String localIp, Long id) {
		UserLoginRecord record = audit.find(UserLoginRecord.class, 
											new UserLoginRecordPK(id, localIp));
		if(record == null) {
			throw new EntityNotFoundException(AUT0001E_RECORD_NOT_FOUND,
											  localIp,
											  id);
		}
		
		boolean validSignature = isValidSignature(record);
		
		return newUserLoginRecordData()
			   .withLoginDate(record.getLoginDate())
			   .withLoginState(record.getState())
			   .withRemoteIp(record.getRemoteIp())
			   .withValid(validSignature)
			   .withUserAgent(record.getUserAgent())
			   .withUserId(record.getUserId())
			   .build();
	}

	private boolean isValidSignature(UserLoginRecord record) {
		String rawMessage = rawMessage(record.getLocalIp(),
									   record.getId(),
									   record.getRemoteIp(), 
				   					   record.getUserAgent(), 
				   					   record.getUserId(), 
				   					   record.getState(), 
				   					   record.getPreviousLogRecord(),
				   					   record.getLoginDate());
		
		return isValidSignature(rawMessage,
								record.getSignature());
	}
	
	private boolean isValidSignature(String rawMessage, byte[] signature) {
		return hmacSha256(secret).isValid(rawMessage,signature);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<UserLoginAuditLogRecordData> findUserLoginAuditLogRecords(UserLoginAuditLogQuery query) {

		List<String> filter = new LinkedList<>();
		List<Object> args = new LinkedList<>();
		
		if(query.getFromLoginDate() != null) {
			filter.add("l.tslogin >= ?");
			args.add(query.getFromLoginDate());
		}
		
		if(query.getToLoginDate() != null) {
			filter.add("l.tslogin <= ?");
			args.add(query.getToLoginDate());
		}
		
		if(query.getUserIdPattern() != null && query.getUserIdPattern().length() > 0) {
			filter.add("l.userid ~ ?");
			args.add(query.getUserIdPattern());
		}
		
		if(query.getRemoteIp() != null && query.getRemoteIp().length() > 0) {
			filter.add("l.remoteip = ?");
			args.add(query.getRemoteIp());
		}
		
		StringBuilder where = new StringBuilder();
		if(!filter.isEmpty()) {
			where.append(" WHERE ")
			     .append(filter.remove(0));
			while(!filter.isEmpty()) {
				where.append(" AND ")
				      .append(filter.remove(0));
			}
			where.append(" ");
		}
		String sql = "SELECT l.localip, l.id, l.remoteip, l.useragent, l.userid, "+
		                     "l.loginstate, l.previous_user_login_audit_log_id, "+
		                     "l.tslogin, l.signature, r.id "+
		              "FROM AUTH.USER_LOGIN_AUDIT_LOG l "+
		              "LEFT OUTER JOIN AUTH.USER_LOGIN_AUDIT_LOG r "+
		              "ON l.previous_user_login_audit_log_id = r.id AND l.localip = r.localip ";

		 
		return db.executeQuery(prepare(sql+where+"ORDER BY l.tslogin DESC FETCH FIRST "+query.getLimit()+" ROWS ONLY",args), 
							   rs -> newUserLoginRecordData()
							   		 .withLocalIp(rs.getString(1))
							   		 .withId(rs.getLong(2))
								     .withRemoteIp(rs.getString(3))
							   		 .withUserAgent(rs.getString(4))
							   		 .withUserId(new UserId(rs.getString(5)))
							   		 .withLoginState(UserLoginState.valueOf(rs.getString(6)))
							   		 .withLoginDate(rs.getTimestamp(8))
							   		 .withValid(rs.getLong(7) == rs.getLong(10) && 
							   		 					 isValidSignature(rawMessage(rs.getString(1),
							   				 										 rs.getLong(2),
							   				 										 rs.getString(3),
							   				 										 rs.getString(4),
							   				 										 rs.getString(5),
							   				 										 rs.getString(6),
							   				 										 rs.getLong(7),
							   				 										 rs.getTimestamp(8).getTime()), 
							   				 							  			 decodeBase64String(rs.getString(9))))
							   		 .build());
	}
	
	
}
