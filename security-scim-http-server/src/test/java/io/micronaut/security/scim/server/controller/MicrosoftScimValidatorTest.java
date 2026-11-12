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
package io.micronaut.security.scim.server.controller;

import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.scim.core.Group;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.server.protocol.ScimError;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@MicronautTest(transactional = false)
@Property(name = "spec.name", value = "MicrosoftScimValidatorTest")
@Property(name = "datasources.default.url",
    value = "jdbc:h2:mem:microsoft-scim-validator;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;DATABASE_TO_UPPER=false")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.password", value = "")
@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "micronaut.security.scim.data.dialect", value = "H2")
class MicrosoftScimValidatorTest {
    private static final String USER_NAME = "roscoe.quitzon@okeeferau.co.uk";

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void createsAndFindsTheMicrosoftScimValidatorUserWithoutChangingValues() throws IOException {
        BlockingHttpClient client = httpClient.toBlocking();
        String requestBody = """
            {
              "active": true,
              "addresses": [
                {
                  "type": "work",
                  "formatted": "AWJVTOGKVRTC",
                  "streetAddress": "2710 Kling Station",
                  "locality": "ACGWGWBAWTLM",
                  "region": "JMESHVNUZMYS",
                  "postalCode": "yk32 9vb",
                  "primary": true,
                  "country": "Afghanistan"
                }
              ],
              "displayName": "ARDUMNRGUQYO",
              "emails": [
                {
                  "type": "work",
                  "value": "sandy_daugherty@cummerataschulist.com",
                  "primary": true
                }
              ],
              "locale": "KHHIFQJZTQWT",
              "name": {
                "givenName": "Kaleb",
                "familyName": "Jany",
                "formatted": "Vivienne",
                "middleName": "Liliana",
                "honorificPrefix": "Kayli",
                "honorificSuffix": "Bruce"
              },
              "nickName": "GHOVFXUZEEAT",
              "phoneNumbers": [
                {
                  "type": "work",
                  "value": "73-798-9278",
                  "primary": true
                },
                {
                  "type": "mobile",
                  "value": "73-798-9278"
                },
                {
                  "type": "fax",
                  "value": "73-798-9278"
                }
              ],
              "preferredLanguage": "cy-GB",
              "profileUrl": "PIOVOJKQFOZG",
              "roles": [
                {
                  "primary": "True",
                  "display": "TXBBCYAQNNGX",
                  "value": "KCKMIRBDHVNQ",
                  "type": "HQDTFSMLXNPX"
                }
              ],
              "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
              ],
              "timezone": "Africa/Monrovia",
              "title": "AVLICEPXQDWA",
              "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "ORHYMRGXYQGG",
                "department": "VGSXGOVOSHYX",
                "costCenter": "ILEJBJINMJCK",
                "organization": "AQYBIFOCLBNC",
                "division": "OJEDLGHLEFFF",
                "manager": {
                  "value": "QMZPQIGQSHGH"
                }
              },
              "userName": "roscoe.quitzon@okeeferau.co.uk",
              "userType": "VJABPPTOUDXR"
            }
            """;

        HttpResponse<User> created = client.exchange(
            HttpRequest.POST("/scim/v2/Users", requestBody)
                .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
                .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE),
            User.class
        );

        assertEquals(HttpStatus.CREATED, created.getStatus());
        assertNotNull(created.body().getId());
        assertNotNull(created.body().getMeta());
        assertEquals(created.body().getMeta().location(),
            created.getHeaders().get(HttpHeaders.CONTENT_LOCATION));

        HttpResponse<String> found = client.exchange(
            HttpRequest.GET("/scim/v2/Users?filter=userName%20eq%20%22roscoe.quitzon%40okeeferau.co.uk%22")
                .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE),
            String.class
        );

        assertEquals(HttpStatus.OK, found.getStatus());
        Map<?, ?> listResponse = jsonMapper.readValue(found.body(), Map.class);
        assertEquals(1, ((Number) listResponse.get("totalResults")).intValue());
        Map<?, ?> user = firstMap(listResponse, "Resources");
        assertEquals(USER_NAME, user.get("userName"));
        Map<?, ?> role = firstMap(user, "roles");
        assertEquals("KCKMIRBDHVNQ", role.get("value"));
        assertEquals("HQDTFSMLXNPX", role.get("type"));
        assertEquals("TXBBCYAQNNGX", role.get("display"));
        assertEquals(Boolean.TRUE, role.get("primary"));
    }

    @Test
    void addsAttributesWithMicrosoftScimValidatorFilteredPaths() {
        BlockingHttpClient client = httpClient.toBlocking();
        User created = createUser(client, """
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
              "userName": "buddy_wiegand@gulgowski.name"
            }
            """);

        User patched = patchUser(client, created.getId(), """
            {
              "Operations": [
                {
                  "op": "add",
                  "path": "emails[type eq \\"work\\"].value",
                  "value": "jaylen@mclaughlin.biz"
                },
                {
                  "op": "add",
                  "path": "emails[type eq \\"work\\"].primary",
                  "value": true
                },
                {
                  "op": "add",
                  "path": "addresses[type eq \\"work\\"].formatted",
                  "value": "FQRTEFXTAAZO"
                },
                {
                  "op": "add",
                  "path": "addresses[type eq \\"work\\"].streetAddress",
                  "value": "250 Callie Ways"
                },
                {
                  "op": "add",
                  "path": "addresses[type eq \\"work\\"].primary",
                  "value": true
                },
                {
                  "op": "add",
                  "path": "phoneNumbers[type eq \\"work\\"].value",
                  "value": "66-177-3998"
                },
                {
                  "op": "add",
                  "path": "phoneNumbers[type eq \\"mobile\\"].value",
                  "value": "66-177-3998"
                },
                {
                  "op": "add",
                  "path": "roles[primary eq \\"True\\"].display",
                  "value": "ZMLXVACGNQRU"
                },
                {
                  "op": "add",
                  "path": "roles[primary eq \\"True\\"].value",
                  "value": "IMLJJNWGGVAR"
                },
                {
                  "op": "add",
                  "value": {
                    "active": true,
                    "displayName": "MWPZCRLZPKJA",
                    "name.givenName": "Jovan",
                    "name.familyName": "Karina",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber": "CSJOXDRQMYPE",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department": "ZWKPZIITMALV"
                  }
                }
              ],
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]
            }
            """);

        assertEquals("jaylen@mclaughlin.biz", patched.getEmails().getFirst().value());
        assertEquals("work", patched.getEmails().getFirst().type());
        assertEquals(true, patched.getEmails().getFirst().primary());
        assertEquals("250 Callie Ways", patched.getAddresses().getFirst().streetAddress());
        assertEquals("work", patched.getAddresses().getFirst().type());
        assertEquals("66-177-3998", patched.getPhoneNumbers().getFirst().value());
        assertEquals("work", patched.getPhoneNumbers().getFirst().type());
        assertEquals("mobile", patched.getPhoneNumbers().get(1).type());
        assertEquals("ZMLXVACGNQRU", patched.getRoles().getFirst().display());
        assertEquals("IMLJJNWGGVAR", patched.getRoles().getFirst().value());
        assertEquals(true, patched.getRoles().getFirst().primary());
        assertEquals("MWPZCRLZPKJA", patched.getDisplayName());
        assertEquals("Jovan", patched.getName().givenName());
        assertEquals("Karina", patched.getName().familyName());
        assertEquals("CSJOXDRQMYPE", patched.getEnterpriseUser().employeeNumber());
        assertEquals("ZWKPZIITMALV", patched.getEnterpriseUser().department());
    }

    @Test
    void replacesAttributesWithMicrosoftScimValidatorFilteredPaths() {
        BlockingHttpClient client = httpClient.toBlocking();
        User created = createUser(client, """
            {
              "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
              ],
              "userName": "megane@oconnell.info",
              "emails": [{"type": "work", "value": "old@example.com", "primary": true}],
              "addresses": [{"type": "work", "streetAddress": "Old address", "primary": true}],
              "phoneNumbers": [
                {"type": "work", "value": "old-work"},
                {"type": "mobile", "value": "old-mobile"}
              ],
              "roles": [{"primary": "True", "display": "Old role", "value": "old"}],
              "name": {"givenName": "Old"},
              "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "old-employee"
              }
            }
            """);

        User patched = patchUser(client, created.getId(), """
            {
              "Operations": [
                {
                  "op": "replace",
                  "path": "emails[type eq \\"work\\"].value",
                  "value": "tracey@kub.us"
                },
                {
                  "op": "replace",
                  "path": "addresses[type eq \\"work\\"].streetAddress",
                  "value": "968 Flatley Ville"
                },
                {
                  "op": "replace",
                  "path": "phoneNumbers[type eq \\"work\\"].value",
                  "value": "63-916-6222"
                },
                {
                  "op": "replace",
                  "path": "phoneNumbers[type eq \\"mobile\\"].value",
                  "value": "63-916-6222"
                },
                {
                  "op": "replace",
                  "path": "roles[primary eq \\"True\\"].display",
                  "value": "FEXPUJKNYMQT"
                },
                {
                  "op": "replace",
                  "path": "roles[primary eq \\"True\\"].value",
                  "value": "YKWVBFXNHQEI"
                },
                {
                  "op": "replace",
                  "value": {
                    "displayName": "LNAKMWWIOJDT",
                    "name.givenName": "Linda",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber": "PKBWWISEVGJL"
                  }
                }
              ],
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]
            }
            """);

        assertEquals("tracey@kub.us", patched.getEmails().getFirst().value());
        assertEquals("968 Flatley Ville", patched.getAddresses().getFirst().streetAddress());
        assertEquals("63-916-6222", patched.getPhoneNumbers().getFirst().value());
        assertEquals("63-916-6222", patched.getPhoneNumbers().get(1).value());
        assertEquals("FEXPUJKNYMQT", patched.getRoles().getFirst().display());
        assertEquals("YKWVBFXNHQEI", patched.getRoles().getFirst().value());
        assertEquals("LNAKMWWIOJDT", patched.getDisplayName());
        assertEquals("Linda", patched.getName().givenName());
        assertEquals("PKBWWISEVGJL", patched.getEnterpriseUser().employeeNumber());
    }

    @Test
    void acceptsMicrosoftScimValidatorScalarManagerPatchValues() {
        BlockingHttpClient client = httpClient.toBlocking();
        User created = createUser(client, """
            {
              "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
              ],
              "userName": "manager-patch@example.com",
              "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "701984",
                "manager": {"value": "old-manager"}
              }
            }
            """);

        User withManager = patchUser(client, created.getId(), """
            {
              "Operations": [{
                "op": "add",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                "value": "ea891e07-6556-43de-adac-fe8c383783a7"
              }],
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]
            }
            """);
        assertEquals("ea891e07-6556-43de-adac-fe8c383783a7",
            withManager.getEnterpriseUser().manager().value());
        assertEquals("701984", withManager.getEnterpriseUser().employeeNumber());

        User withoutManager = patchUser(client, created.getId(), """
            {
              "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                "value": ""
              }],
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]
            }
            """);
        assertNull(withoutManager.getEnterpriseUser().manager());
        assertEquals("701984", withoutManager.getEnterpriseUser().employeeNumber());
    }

    @Test
    void rejectsDuplicateMicrosoftScimValidatorGroup() {
        BlockingHttpClient client = httpClient.toBlocking();
        String requestBody = """
            {
              "displayName": "XINQFSYIPZRG",
              "externalId": "c7e4aa67-7a02-4dce-b063-e478dd982d63",
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
            }
            """;

        HttpRequest<String> request = HttpRequest.POST("/scim/v2/Groups", requestBody)
            .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
            .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE);
        HttpResponse<Group> created = client.exchange(request, Group.class);
        assertEquals(HttpStatus.CREATED, created.getStatus());
        assertEquals(1, created.getHeaders().getAll(HttpHeaders.LOCATION).size());
        assertEquals(created.body().getMeta().location(), created.getHeaders().get(HttpHeaders.LOCATION));

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request, ScimError.class));
        assertEquals(HttpStatus.CONFLICT, exception.getStatus());
        ScimError error = exception.getResponse().getBody(ScimError.class).orElseThrow();
        assertEquals("409", error.status());
        assertEquals(ScimErrorType.UNIQUENESS, error.scimType());
    }

    private static User createUser(BlockingHttpClient client, String requestBody) {
        HttpResponse<User> response = client.exchange(
            HttpRequest.POST("/scim/v2/Users", requestBody)
                .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
                .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE),
            User.class
        );
        assertEquals(HttpStatus.CREATED, response.getStatus());
        assertNotNull(response.body().getId());
        return response.body();
    }

    private static User patchUser(BlockingHttpClient client, String id, String requestBody) {
        HttpResponse<User> response = client.exchange(
            HttpRequest.PATCH("/scim/v2/Users/" + id, requestBody)
                .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
                .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE),
            User.class
        );
        assertEquals(HttpStatus.OK, response.getStatus());
        return response.body();
    }

    private static Map<?, ?> firstMap(Map<?, ?> source, String key) {
        List<?> values = (List<?>) source.get(key);
        return (Map<?, ?>) values.getFirst();
    }
}
