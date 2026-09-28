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

import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class DiscoveryResourceSerdeTest {

    @Test
    void deserializesServiceProviderConfiguration(JsonMapper jsonMapper) throws IOException {
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
                  "type": "oauthbearertoken",
                  "name": "OAuth Bearer Token",
                  "description": "Authentication scheme using the OAuth Bearer Token Standard",
                  "specUri": "http://www.rfc-editor.org/info/rfc6750",
                  "documentationUri": "http://example.com/help/oauth.html"
                }
              ]
            }
            """, ServiceProviderConfig.class);

        assertEquals(1000, config.getBulk().maxOperations());
        assertEquals(200, config.getFilter().maxResults());
        assertTrue(config.getSort().supported());
        assertEquals(AuthenticationScheme.OAUTH_BEARER_TOKEN,
            config.getAuthenticationSchemes().get(0).type());
    }

    @Test
    void deserializesResourceType(JsonMapper jsonMapper) throws IOException {
        ResourceType resourceType = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
              "id": "User",
              "name": "User",
              "endpoint": "/Users",
              "description": "User Account",
              "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
              "schemaExtensions": [
                {
                  "schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                  "required": true
                }
              ]
            }
            """, ResourceType.class);

        assertEquals("/Users", resourceType.getEndpoint());
        assertEquals(SchemaUris.USER, resourceType.getSchema());
        assertTrue(resourceType.getSchemaExtensions().get(0).required());
    }

    @Test
    void schemaAttributeCharacteristicsUseRfcWireValues(JsonMapper jsonMapper) throws IOException {
        Schema schema = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
              "id": "urn:example:params:scim:schemas:Widget",
              "name": "Widget",
              "attributes": [
                {
                  "name": "serialNumber",
                  "type": "string",
                  "multiValued": false,
                  "description": "The widget serial number",
                  "required": true,
                  "caseExact": true,
                  "mutability": "immutable",
                  "returned": "always",
                  "uniqueness": "global"
                }
              ]
            }
            """, Schema.class);

        AttributeDefinition attribute = schema.getAttributes().get(0);
        assertEquals(AttributeType.STRING, attribute.type());
        assertEquals(Mutability.IMMUTABLE, attribute.mutability());
        assertEquals(Returned.ALWAYS, attribute.returned());
        assertEquals(Uniqueness.GLOBAL, attribute.uniqueness());

        String encoded = jsonMapper.writeValueAsString(schema);
        assertTrue(encoded.contains("\"mutability\":\"immutable\""));
        assertTrue(encoded.contains("\"type\":\"string\""));
        assertFalse(encoded.contains("IMMUTABLE"));
    }
}
