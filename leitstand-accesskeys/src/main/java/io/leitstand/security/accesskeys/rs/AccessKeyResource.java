/*
 * Copyright 2020 RtBrick Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.leitstand.security.accesskeys.rs;
import static io.leitstand.commons.model.StringUtil.isEmptyString;
import static io.leitstand.security.accesskeys.rs.Scopes.ADM;
import static io.leitstand.security.accesskeys.rs.Scopes.ADM_ACCESSKEY;
import static io.leitstand.security.accesskeys.rs.Scopes.ADM_ACCESSKEY_READ;
import static io.leitstand.security.accesskeys.rs.Scopes.ADM_READ;
import static io.leitstand.security.accesskeys.service.AccessKeyData.newAccessKey;
import static io.leitstand.security.accesskeys.service.AccessKeyName.accessKeyName;
import static java.lang.String.format;
import static java.net.URI.create;
import static javax.servlet.http.HttpServletResponse.SC_CONFLICT;
import static javax.ws.rs.client.Entity.json;
import static javax.ws.rs.client.Entity.text;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.MediaType.TEXT_PLAIN;
import static javax.ws.rs.core.Response.created;
import static javax.ws.rs.core.Response.noContent;
import static javax.ws.rs.core.Response.ok;
import static javax.ws.rs.core.Response.status;

import java.util.List;

import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.accesskeys.flow.CreateAccessKeyFlow;
import io.leitstand.security.accesskeys.flow.RenewAccessKeyFlow;
import io.leitstand.security.accesskeys.service.AccessKeyData;
import io.leitstand.security.accesskeys.service.AccessKeyMetaData;
import io.leitstand.security.accesskeys.service.AccessKeyService;
import io.leitstand.security.auth.Scopes;
import io.leitstand.security.auth.accesskey.AccessKeyId;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskeys.AccessKeyEncodingService;

@Resource
@Path("/accesskeys")
@Scopes({ADM,ADM_ACCESSKEY})
@Consumes(APPLICATION_JSON)
@Produces(APPLICATION_JSON)
public class AccessKeyResource {

	@Inject
	private AccessKeyService service;
	
	@Inject
	private AccessKeyEncodingService encoder;
	
	@Inject
	private Messages messages;
	
	@GET
	@Scopes({ADM,ADM_READ,ADM_ACCESSKEY,ADM_ACCESSKEY_READ})
	public List<AccessKeyMetaData> findAccessKey(@QueryParam("filter") @DefaultValue(".*") String filter){
		return service.findAccessKeys(filter);
	}
	
	@GET
	@Path("/{key_id}")
	@Scopes({ADM,ADM_READ,ADM_ACCESSKEY,ADM_ACCESSKEY_READ})
	public AccessKeyData getAccessKey(@PathParam("key_id") @Valid AccessKeyId accessKeyId){
		return service.getAccessKey(accessKeyId);
	}
	
	@POST
	@Path("/{key_id}/_renew")
	public Response renewAccessKey(@PathParam("key_id") @Valid AccessKeyId accessKeyId){
		RenewAccessKeyFlow renewFlow = new RenewAccessKeyFlow(service);
		renewFlow.renew(accessKeyId);
		return created(create(format("/accesskeys/%s",
									 renewFlow.getNewAccessTokenId())))
			   .entity(text(renewFlow.getNewAccessToken()))
			   .build();
	}
	
	@PUT
	@Path("/{key_id}/description")
	@Consumes(TEXT_PLAIN)
	public Messages updateAccessKeyDescription(@PathParam("key_id") @Valid AccessKeyId accessKeyId,
											   String description){
		service.updateAccessKey(accessKeyId, 
								description);
		return messages;
	}
	
	@POST
	public Response createNewAccessKey(@Valid AccessKeyData accessKeyData) {
		CreateAccessKeyFlow flow = new CreateAccessKeyFlow(service, messages);
		String accessKey = flow.tryCreateAccessKey(accessKeyData);
		if(isEmptyString(accessKey)) {
			return status(SC_CONFLICT)
				   .entity(messages)
				   .build();
		}
		return created(create(format("/accesskeys/%s",
									 accessKeyData.getAccessKeyId())))
			   .entity("\""+accessKey+"\"")
			   .build();
	}
	
	@DELETE
	@Path("/{key_id}")
	public Response removeAccessKey(@PathParam("key_id") @Valid AccessKeyId accessKeyId) {
		service.removeAccessKey(accessKeyId);
		if(messages.isEmpty()) {
			return noContent().build();
		}
		return ok(json(messages)).build();
	}
	
	@POST
	@Path("/_validate")	
	@Consumes(TEXT_PLAIN)
	public AccessKeyData validate(String accessToken) {
	    try {
    		ApiAccessKey key = encoder.decode(accessToken);
    		return service.getAccessKey(key.getId());
	    } catch (AccessDeniedException e) {
	        // The access token is either malformed or has an invalid signature.
	        // However, since we verify another token (not the token to authorize the request),
	        // we map the AccessDeniedException to an unprocessable entity exception, 
	        // because the request entity conveys the access token to validate.
	        throw new UnprocessableEntityException(e.getReason());
	    }
	}
	
	@POST
	@Path("/_restore")
	@Consumes(TEXT_PLAIN)
	public AccessKeyData restore(String accessToken) {
	    try{
    	    ApiAccessKey key = encoder.decode(accessToken);
    	    service.createAccessKey(newAccessKey()
    	                            .withAccessKeyId(key.getId())
    	                            .withAccessKeyName(accessKeyName(key.getUserName()))
    	                            .withScopes(key.getScopes())
    	                            .build());
    	    return service.getAccessKey(key.getId());
	    } catch (AccessDeniedException e) {
            // The access token is either malformed or has an invalid signature.
            // However, since we verify another token (not the token to authorize the request),
            // we map the AccessDeniedException to an unprocessable entity exception, 
            // because the request entity conveys the access token to validate.
	        throw new UnprocessableEntityException(e.getReason());
	    }
	}
	
}
