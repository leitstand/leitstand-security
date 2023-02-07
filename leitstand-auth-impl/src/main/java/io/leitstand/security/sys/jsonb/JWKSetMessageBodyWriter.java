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
package io.leitstand.security.sys.jsonb;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * Marshals a <code>com.nimbusds.jose.jwk.JWKSet</code> entity.
 */
@Provider
@Produces(APPLICATION_JSON)
public class JWKSetMessageBodyWriter implements MessageBodyWriter<JWKSet> {

    /**
     * Returns always <code>0</code>.
     * {@inheritDoc}
     */
    @Override
    public long getSize(JWKSet object, 
                        Class<?> type,
                        Type genericType, 
                        Annotation[] annotations, 
                        MediaType mediaType) {
        return 0;
    }

    /**
     * Returns always <code>true</code>.
     * {@inheritDoc}
     */
    @Override
    public boolean isWriteable(Class<?> type, 
                               Type genericType, 
                               Annotation[] annotations, 
                               MediaType mediaType) {
        return true;
    }

    /**
     * Marshals <code>com.nimbusds.jose.jwk.JWKSet</code> to a string in <code>UTF-8</code> character encoding.
     * {@inheritDoc}
     */
    @Override
    public void writeTo(JWKSet object,
                        Class<?> type,
                        Type genericType,
                        Annotation[] annotations,
                        MediaType mediaType,
                        MultivaluedMap<String, Object> httpHeaders,
                        OutputStream entityStream)
                        throws IOException {
        entityStream.write(object.toString().getBytes("UTF-8"));
    }

}
