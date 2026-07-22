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
package io.micronaut.security.scim.server.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScimMessageSchemasTest {
    private static final String PREFIX = "urn:ietf:params:scim:api:messages:2.0:";

    @Test
    void exposesRfcMessageSchemaUris() {
        assertEquals(PREFIX + "ListResponse", ScimMessageSchemas.LIST_RESPONSE);
        assertEquals(PREFIX + "SearchRequest", ScimMessageSchemas.SEARCH_REQUEST);
        assertEquals(PREFIX + "PatchOp", ScimMessageSchemas.PATCH_OPERATION);
        assertEquals(PREFIX + "BulkRequest", ScimMessageSchemas.BULK_REQUEST);
        assertEquals(PREFIX + "BulkResponse", ScimMessageSchemas.BULK_RESPONSE);
        assertEquals(PREFIX + "Error", ScimMessageSchemas.ERROR);
    }
}
