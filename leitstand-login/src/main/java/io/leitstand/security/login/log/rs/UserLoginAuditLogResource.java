/*
 * (c) RtBrick, Inc All rights reserved, 2015 2019
 */
package io.leitstand.security.login.log.rs;

import static io.leitstand.commons.rs.ResourceUtil.tryParseDate;
import static io.leitstand.commons.rs.ResourceUtil.tryParseInt;
import static io.leitstand.security.login.log.service.UserLoginAuditLogQuery.newUserLoginAuditLogQuery;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.util.List;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;

import io.leitstand.security.login.log.service.UserLoginAuditLogQuery;
import io.leitstand.security.login.log.service.UserLoginAuditLogRecordData;
import io.leitstand.security.login.log.service.UserLoginAuditLogService;

/**
 * The REST resource to query user login audit log records.
 */
@RequestScoped
@Path("/login")
@Produces(APPLICATION_JSON)
public class UserLoginAuditLogResource {

	@Inject
	private UserLoginAuditLogService service;
	
	/**
	 * Returns a single user login audit log record.
	 * @param localIp the IP address of the service that has written the log record
	 * @param id the sequence number of the log record.
	 * @return the log record
	 */
	@GET
	@Path("/records/{localip}/{id}")
	public UserLoginAuditLogRecordData getLogRecord(@PathParam("localip") String localIp, 
											        @PathParam("id") Long id) {
		return service.getUserLoginRecord(localIp, id);
	}

	/**
	 * Runs a query for user audit login records. All query parameters are optional.
	 * @param from the from timestamp in ISO date format. Records must be written after this timestamp, if specified
	 * @param to the to timestamp in ISO date format. Records must be written before this timstemp, if specified.
	 * @param remoteIp the IP address from which the login was attempted, if specified.
	 * @param userName the user ID pattern as POSIX regular expression the user ID in the record must match, if specified
	 * @param limit the maximum number of returned items. Defaults to 100 if not specified.
	 * @return a list of matching user login audit log records or an empty list if no matching records were found.
	 */
	@GET
	@Path("/records")
	public List<UserLoginAuditLogRecordData> findLogRecords(@QueryParam("from") String from,
														    @QueryParam("to") String to,
														    @QueryParam("remote_ip") String remoteIp,
														    @QueryParam("user") String userName,
														    @QueryParam("limit") @DefaultValue("100") String limit) {
		
		UserLoginAuditLogQuery query = newUserLoginAuditLogQuery()
									   .withFromLoginDate(tryParseDate(from))
									   .withToLoginDate(tryParseDate(to))
									   .withRemoteIp(remoteIp)
									   .withUserNamePattern(userName)
									   .withLimit(tryParseInt(limit,100))
									   .build();
		
		return service.findUserLoginAuditLogRecords(query);
	}
	
}
