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
package io.micronaut.security.scim.data.jdbc.http.service;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(transactional = false)
class JdbcScimHttpServerTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void jdbcUserServiceActivatesTheHttpUserRoutes() {
        BlockingHttpClient client = httpClient.toBlocking();
        User user = new User();
        user.setUserName("http-jdbc-" + System.nanoTime() + "@example.com");

        HttpResponse<User> created = client.exchange(
            HttpRequest.POST("/scim/v2/Users", user)
                .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
                .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE),
            User.class
        );

        assertEquals(HttpStatus.CREATED, created.getStatus());
        assertNotNull(created.body().getId());
        assertTrue(created.getHeaders().contains(HttpHeaders.LOCATION));

        HttpResponse<User> found = client.exchange(
            HttpRequest.GET("/scim/v2/Users/" + created.body().getId())
                .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE),
            User.class
        );
        assertEquals(user.getUserName(), found.body().getUserName());

        assertEquals(HttpStatus.NO_CONTENT, client.exchange(
            HttpRequest.DELETE("/scim/v2/Users/" + created.body().getId())
                .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
        ).getStatus());
    }
}
