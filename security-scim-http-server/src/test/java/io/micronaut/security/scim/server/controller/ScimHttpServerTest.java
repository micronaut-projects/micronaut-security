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

import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Patch;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Put;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.scim.core.Group;
import io.micronaut.security.scim.core.Meta;
import io.micronaut.security.scim.core.ResourceType;
import io.micronaut.security.scim.core.Schema;
import io.micronaut.security.scim.core.ScimResource;
import io.micronaut.security.scim.core.ServiceProviderConfig;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.filter.ScimFilter;
import io.micronaut.security.scim.server.model.ScimPage;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimBulkMethod;
import io.micronaut.security.scim.server.protocol.ScimBulkResponse;
import io.micronaut.security.scim.server.protocol.ScimBulkResponseOperation;
import io.micronaut.security.scim.server.protocol.ScimError;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.protocol.ScimMessageSchemas;
import io.micronaut.security.scim.server.protocol.ScimPatchOperationType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.service.ScimBulkService;
import io.micronaut.security.scim.server.service.ScimDiscoveryService;
import io.micronaut.security.scim.server.service.ScimGroupService;
import io.micronaut.security.scim.server.service.ScimMeService;
import io.micronaut.security.scim.server.service.ScimRootSearchService;
import io.micronaut.security.scim.server.service.ScimUserService;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest
@Property(name = "spec.name", value = "ScimHttpServerTest")
class ScimHttpServerTest {
    private static final MediaType SCIM_JSON = ScimMediaType.APPLICATION_SCIM_JSON_TYPE;

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    TestUserService userService;

    @Inject
    ScimMeController meController;

    @Test
    void createsAndRetrievesAUserWithScimHeaders() {
        BlockingHttpClient client = httpClient.toBlocking();
        String json = """
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
              "userName": "bjensen@example.com",
              "name": {"formatted": "Ms. Barbara J Jensen III"},
              "active": true
            }
            """;

        HttpResponse<User> created = client.exchange(HttpRequest.POST("/scim/v2/Users", json)
            .contentType(SCIM_JSON)
            .accept(SCIM_JSON), User.class);

        assertEquals(HttpStatus.CREATED, created.getStatus());
        assertEquals("https://example.com/scim/v2/Users/2819c223", created.getHeaders().get(HttpHeaders.LOCATION));
        assertEquals("https://example.com/scim/v2/Users/2819c223",
            created.getHeaders().get(HttpHeaders.CONTENT_LOCATION));
        assertEquals("W/\"1\"", created.getHeaders().get(HttpHeaders.ETAG));
        assertEquals(SCIM_JSON, created.getContentType().orElseThrow());
        assertEquals("2819c223", created.body().getId());

        HttpResponse<User> found = client.exchange(HttpRequest.GET("/scim/v2/Users/2819c223")
            .accept(MediaType.APPLICATION_JSON_TYPE), User.class);
        assertEquals(HttpStatus.OK, found.getStatus());
        assertEquals(SCIM_JSON, found.getContentType().orElseThrow());
        assertEquals("https://example.com/scim/v2/Users/2819c223",
            found.getHeaders().get(HttpHeaders.CONTENT_LOCATION));

        HttpResponse<?> notModified = client.exchange(HttpRequest.GET("/scim/v2/Users/2819c223")
            .header(HttpHeaders.IF_NONE_MATCH, "\"1\"")
            .accept(SCIM_JSON));
        assertEquals(HttpStatus.NOT_MODIFIED, notModified.getStatus());
    }

    @Test
    void parsesSearchParametersForTheApplicationService() {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<String> response = client.exchange(HttpRequest.GET(
                "/scim/v2/Users?filter=userName%20eq%20%22bjensen%40example.com%22&attributes=userName&startIndex=0&count=5000")
            .accept(SCIM_JSON), String.class);

        assertEquals(HttpStatus.OK, response.getStatus());
        ScimQuery query = userService.lastQuery.get();
        assertNotNull(query);
        assertEquals(1, query.startIndex());
        assertEquals(1000, query.count());
        assertEquals(List.of("userName"), query.attributes().attributes());
        assertInstanceOf(ScimFilter.Comparison.class, query.filter());
        assertTrue(response.body().contains("\"Resources\""));

        client.exchange(HttpRequest.GET("/scim/v2/Users?count=-1").accept(SCIM_JSON));
        assertEquals(0, userService.lastQuery.get().count());
    }

    @Test
    void userListResponseIncludesResourcesWhenTheCurrentPageIsEmpty() {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<String> response = client.exchange(HttpRequest.GET("/scim/v2/Users?count=0")
            .accept(SCIM_JSON), String.class);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertTrue(response.body().contains("\"Resources\":[]"));
    }

    @Test
    void supportsPostSearchAndPatch() {
        BlockingHttpClient client = httpClient.toBlocking();
        String search = """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
              "filter": "userName pr",
              "count": 5
            }
            """;
        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.POST("/scim/v2/Users/.search", search)
            .contentType(SCIM_JSON).accept(SCIM_JSON)).getStatus());

        String patch = """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [{"op": "replace", "path": "active", "value": false}]
            }
            """;
        HttpResponse<User> response = client.exchange(HttpRequest.PATCH("/scim/v2/Users/2819c223", patch)
            .contentType(SCIM_JSON).accept(SCIM_JSON), User.class);
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(ScimPatchOperationType.REPLACE, userService.lastPatch.get().operations().get(0).op());
    }

    @Test
    void returnsRfcErrorsForInvalidProtocolRequestsAndMissingResources() {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException invalidFilter = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/scim/v2/Users?filter=userName%20eq%20unquoted")
                .accept(SCIM_JSON), ScimError.class));
        assertEquals(HttpStatus.BAD_REQUEST, invalidFilter.getStatus());
        ScimError filterError = invalidFilter.getResponse().getBody(ScimError.class).orElseThrow();
        assertEquals("400", filterError.status());
        assertEquals(ScimErrorType.INVALID_FILTER, filterError.scimType());

        HttpClientResponseException missing = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/scim/v2/Users/missing").accept(SCIM_JSON), ScimError.class));
        assertEquals(HttpStatus.NOT_FOUND, missing.getStatus());
        assertEquals(ScimMessageSchemas.ERROR,
            missing.getResponse().getBody(ScimError.class).orElseThrow().schemas().get(0));

        String invalidPatch = """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [{"op": "remove"}]
            }
            """;
        HttpClientResponseException noTarget = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.PATCH("/scim/v2/Users/2819c223", invalidPatch)
                .contentType(SCIM_JSON).accept(SCIM_JSON), ScimError.class));
        assertEquals(ScimErrorType.NO_TARGET,
            noTarget.getResponse().getBody(ScimError.class).orElseThrow().scimType());

        HttpClientResponseException malformed = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.POST("/scim/v2/Users", "{not-json")
                .contentType(SCIM_JSON).accept(SCIM_JSON), ScimError.class));
        assertEquals(HttpStatus.BAD_REQUEST, malformed.getStatus());
        assertEquals(ScimMessageSchemas.ERROR,
            malformed.getResponse().getBody(ScimError.class).orElseThrow().schemas().get(0));

        String missingUserName = """
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"]}
            """;
        HttpClientResponseException invalidUser = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.POST("/scim/v2/Users", missingUserName)
                .contentType(SCIM_JSON).accept(SCIM_JSON), ScimError.class));
        assertEquals(HttpStatus.BAD_REQUEST, invalidUser.getStatus());
        assertEquals(ScimMessageSchemas.ERROR,
            invalidUser.getResponse().getBody(ScimError.class).orElseThrow().schemas().get(0));
    }

    @Test
    void exposesDiscoveryAndOptionalBulkEndpoints() {
        BlockingHttpClient client = httpClient.toBlocking();

        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.GET("/scim/v2/ServiceProviderConfig")
            .accept(SCIM_JSON)).getStatus());
        String schemas = client.retrieve(HttpRequest.GET("/scim/v2/Schemas").accept(SCIM_JSON));
        assertTrue(schemas.contains("urn:ietf:params:scim:schemas:core:2.0:User"));

        String bulk = """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
              "Operations": [{
                "method": "POST",
                "bulkId": "qwerty",
                "path": "/Users",
                "data": {"userName": "Alice"}
              }]
            }
            """;
        String response = client.retrieve(HttpRequest.POST("/scim/v2/Bulk", bulk)
            .contentType(SCIM_JSON).accept(SCIM_JSON));
        assertTrue(response.contains(ScimMessageSchemas.BULK_RESPONSE));
        assertTrue(response.contains("\"status\":\"201\""));

        String rootSearch = """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
              "filter": "id pr"
            }
            """;
        String rootResponse = client.retrieve(HttpRequest.POST("/scim/v2/.search", rootSearch)
            .contentType(SCIM_JSON).accept(SCIM_JSON));
        assertTrue(rootResponse.contains("bjensen@example.com"));

        MutableHttpResponse<?> me = meController.get(HttpRequest.GET("/scim/v2/Me"));
        assertEquals(HttpStatus.PERMANENT_REDIRECT, me.getStatus());
        assertEquals("https://example.com/scim/v2/Users/2819c223", me.getHeaders().get(HttpHeaders.LOCATION));
    }

    @Test
    void controllerMethodsExecuteOnBlockingExecutor() {
        List<Method> routeMethods = List.of(
                ScimBulkController.class,
                ScimDiscoveryController.class,
                ScimGroupController.class,
                ScimMeController.class,
                ScimRootSearchController.class,
                ScimUserController.class)
            .stream()
            .flatMap(type -> Arrays.stream(type.getDeclaredMethods()))
            .filter(ScimHttpServerTest::isRouteMethod)
            .toList();

        assertEquals(26, routeMethods.size());
        for (Method method : routeMethods) {
            ExecuteOn executeOn = method.getAnnotation(ExecuteOn.class);
            assertNotNull(executeOn, () -> method + " is not annotated with @ExecuteOn");
            assertEquals(TaskExecutors.BLOCKING, executeOn.value());
        }
    }

    @Factory
    @Requires(property = "spec.name", value = "ScimHttpServerTest")
    static class TestFactory {
        @Bean
        @Singleton
        TestUserService userService() {
            return new TestUserService();
        }

        @Bean
        @Singleton
        ScimGroupService groupService() {
            return new EmptyGroupService();
        }

        @Bean
        @Singleton
        ScimDiscoveryService discoveryService() {
            return new TestDiscoveryService();
        }

        @Bean
        @Singleton
        ScimBulkService bulkService() {
            return (request, context) -> ScimBulkResponse.of(List.of(
                new ScimBulkResponseOperation(ScimBulkMethod.POST, "qwerty", "W/\"1\"",
                    "https://example.com/scim/v2/Users/2819c223", null, "201")));
        }

        @Bean
        @Singleton
        ScimRootSearchService rootSearchService(TestUserService userService) {
            return (query, context) -> new ScimPage<ScimResource>(
                List.of(userService.user), 1, query.startIndex());
        }

        @Bean
        @Singleton
        ScimMeService meService() {
            return context -> Optional.of(URI.create("https://example.com/scim/v2/Users/2819c223"));
        }
    }

    static final class TestUserService implements ScimUserService {
        private final AtomicReference<ScimQuery> lastQuery = new AtomicReference<>();
        private final AtomicReference<ScimPatchRequest> lastPatch = new AtomicReference<>();
        private User user = user();

        @Override
        public ScimResourceResponse<User> create(User resource, ScimRequestContext context) {
            resource.setId("2819c223");
            resource.setMeta(new Meta("User", "2010-01-23T04:56:22Z", "2011-05-13T04:42:34Z",
                "https://example.com/scim/v2/Users/2819c223", "W/\"1\""));
            user = resource;
            return response(resource);
        }

        @Override
        public Optional<ScimResourceResponse<User>> get(String id, ScimRequestContext context) {
            return id.equals("2819c223") ? Optional.of(response(user)) : Optional.empty();
        }

        @Override
        public ScimPage<User> search(ScimQuery query, ScimRequestContext context) {
            lastQuery.set(query);
            return new ScimPage<>(query.count() == 0 ? List.of() : List.of(user), 1, query.startIndex());
        }

        @Override
        public Optional<ScimResourceResponse<User>> replace(String id, User resource, ScimRequestContext context) {
            if (!id.equals("2819c223")) {
                return Optional.empty();
            }
            user = resource;
            user.setId(id);
            return Optional.of(response(user));
        }

        @Override
        public Optional<ScimResourceResponse<User>> patch(
            String id,
            ScimPatchRequest patch,
            ScimRequestContext context
        ) {
            lastPatch.set(patch);
            return id.equals("2819c223") ? Optional.of(response(user)) : Optional.empty();
        }

        @Override
        public void delete(String id, ScimRequestContext context) {
            if (!id.equals("2819c223")) {
                throw new ScimException(HttpStatus.NOT_FOUND, "User does not exist");
            }
        }

        private static ScimResourceResponse<User> response(User user) {
            return new ScimResourceResponse<>(user,
                URI.create("https://example.com/scim/v2/Users/2819c223"), "W/\"1\"");
        }

        private static User user() {
            User user = new User();
            user.setId("2819c223");
            user.setUserName("bjensen@example.com");
            return user;
        }
    }

    private static final class EmptyGroupService implements ScimGroupService {
        @Override
        public ScimResourceResponse<Group> create(Group resource, ScimRequestContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<ScimResourceResponse<Group>> get(String id, ScimRequestContext context) {
            return Optional.empty();
        }

        @Override
        public ScimPage<Group> search(ScimQuery query, ScimRequestContext context) {
            return new ScimPage<>(List.of(), 0, query.startIndex());
        }

        @Override
        public Optional<ScimResourceResponse<Group>> replace(String id, Group resource, ScimRequestContext context) {
            return Optional.empty();
        }

        @Override
        public Optional<ScimResourceResponse<Group>> patch(
            String id,
            ScimPatchRequest patch,
            ScimRequestContext context
        ) {
            return Optional.empty();
        }

        @Override
        public void delete(String id, ScimRequestContext context) {
        }
    }

    private static final class TestDiscoveryService implements ScimDiscoveryService {
        @Override
        public ScimResourceResponse<ServiceProviderConfig> getServiceProviderConfiguration(
            ScimRequestContext context
        ) {
            ServiceProviderConfig configuration = new ServiceProviderConfig();
            return new ScimResourceResponse<>(configuration,
                URI.create("https://example.com/scim/v2/ServiceProviderConfig"), null);
        }

        @Override
        public List<Schema> getSchemas(ScimRequestContext context) {
            Schema schema = new Schema();
            schema.setId("urn:ietf:params:scim:schemas:core:2.0:User");
            schema.setName("User");
            return List.of(schema);
        }

        @Override
        public List<ResourceType> getResourceTypes(ScimRequestContext context) {
            ResourceType resourceType = new ResourceType();
            resourceType.setId("User");
            resourceType.setName("User");
            resourceType.setEndpoint("/Users");
            resourceType.setSchema("urn:ietf:params:scim:schemas:core:2.0:User");
            return List.of(resourceType);
        }
    }

    private static boolean isRouteMethod(Method method) {
        return method.isAnnotationPresent(Get.class)
            || method.isAnnotationPresent(Post.class)
            || method.isAnnotationPresent(Put.class)
            || method.isAnnotationPresent(Patch.class)
            || method.isAnnotationPresent(Delete.class);
    }
}
