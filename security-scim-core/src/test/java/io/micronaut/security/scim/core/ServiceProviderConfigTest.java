/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.scim.core;

import io.micronaut.context.BeanContext;
import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class ServiceProviderConfigTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void validatesConstraints() {
        ServiceProviderConfig valid = new ServiceProviderConfig();
        valid.setPatch(new SupportedFeature(true));
        valid.setBulk(new BulkFeature(true, 1000, 1048576));
        valid.setFilter(new FilterFeature(true, 200));
        valid.setChangePassword(new SupportedFeature(true));
        valid.setSort(new SupportedFeature(true));
        valid.setEtag(new SupportedFeature(true));
        valid.setAuthenticationSchemes(List.of(new AuthenticationScheme(
            AuthenticationScheme.OAUTH_BEARER_TOKEN,
            "OAuth Bearer Token",
            "Authentication scheme using the OAuth Bearer Token Standard",
            "http://www.rfc-editor.org/info/rfc6750",
            "http://example.com/help/oauth.html"
        )));
        assertTrue(validator.validate(valid).isEmpty());

        Set<String> invalidProperties = validator.validate(new ServiceProviderConfig()).stream()
            .map(violation -> violation.getPropertyPath().toString())
            .collect(Collectors.toSet());
        assertEquals(
            Set.of("patch", "bulk", "filter", "changePassword", "sort", "etag", "authenticationSchemes"),
            invalidProperties
        );
    }

    @Test
    void deserializesRfcExample() throws IOException {
        ServiceProviderConfig config = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
              "documentationUri": "http://example.com/help/scim.html",
              "patch": {"supported": true},
              "bulk": {"supported": true, "maxOperations": 1000, "maxPayloadSize": 1048576},
              "filter": {"supported": true, "maxResults": 200},
              "changePassword": {"supported": true},
              "sort": {"supported": true},
              "etag": {"supported": true},
              "authenticationSchemes": [
                {
                  "name": "OAuth Bearer Token",
                  "description": "Authentication scheme using the OAuth Bearer Token Standard",
                  "specUri": "http://www.rfc-editor.org/info/rfc6750",
                  "documentationUri": "http://example.com/help/oauth.html",
                  "type": "oauthbearertoken",
                  "primary": true
                },
                {
                  "name": "HTTP Basic",
                  "description": "Authentication scheme using the HTTP Basic Standard",
                  "specUri": "http://www.rfc-editor.org/info/rfc2617",
                  "documentationUri": "http://example.com/help/httpBasic.html",
                  "type": "httpbasic"
                }
              ],
              "meta": {
                "location": "https://example.com/v2/ServiceProviderConfig",
                "resourceType": "ServiceProviderConfig",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z"
              }
            }
            """, ServiceProviderConfig.class);

        assertTrue(config.getPatch().supported());
        assertEquals(1000, config.getBulk().maxOperations());
        assertEquals(AuthenticationScheme.OAUTH_BEARER_TOKEN, config.getAuthenticationSchemes().getFirst().type());
    }

    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(ServiceProviderConfig.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(ServiceProviderConfig.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ServiceProviderConfig.class));
    }
}

