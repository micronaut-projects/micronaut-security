package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.core.type.ReturnType;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.bind.RequestBinderRegistry;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.http.uri.UriMatchVariable;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.web.router.UriRouteInfo;
import io.micronaut.web.router.UriRouteMatch;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@MicronautTest(startApplication = false)
class CsrfFilterTest {

    @Test
    void csrfFilterUriMatch(CsrfFilter csrfFilter) {
        assertFalse(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch("/login"));
        assertTrue(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch("/todo/list"));

        HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.POST, "/login", Collections.emptyMap());
        assertTrue(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch(request));
        request = new SimpleHttpRequest<>(HttpMethod.POST, "/todo/list", Collections.emptyMap());
        assertTrue(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch(request));

        assertFalse(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch(createUriRouteMatch("/login")));
        assertTrue(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch(createUriRouteMatch("/todo/list")));
    }

    private static UriRouteMatch createUriRouteMatch(String uri) {
        return new UriRouteMatch() {
            @Override
            public UriRouteInfo getRouteInfo() {
                throw new UnsupportedOperationException();
            }

            @Override
            public HttpMethod getHttpMethod() {
                throw new UnsupportedOperationException();
            }

            @Override
            public @NonNull ExecutableMethod getExecutableMethod() {
                throw new UnsupportedOperationException();
            }

            @Override
            public Object getTarget() {
                throw new UnsupportedOperationException();
            }

            @Override
            public Class getDeclaringType() {
                throw new UnsupportedOperationException();
            }

            @Override
            public Argument[] getArguments() {
                throw new UnsupportedOperationException();
            }

            @Override
            public Object invoke(Object... arguments) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Method getTargetMethod() {
                throw new UnsupportedOperationException();
            }

            @Override
            public ReturnType getReturnType() {
                throw new UnsupportedOperationException();
            }

            @Override
            public String getMethodName() {
                throw new UnsupportedOperationException();
            }

            @Override
            public String getUri() {
                return uri;
            }

            @Override
            public Map<String, Object> getVariableValues() {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<UriMatchVariable> getVariables() {
                throw new UnsupportedOperationException();
            }

            @Override
            public Map<String, UriMatchVariable> getVariableMap() {
                throw new UnsupportedOperationException();
            }

            @Override
            public void fulfill(Map argumentValues) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void fulfillBeforeFilters(RequestBinderRegistry requestBinderRegistry, HttpRequest request) {
                throw new UnsupportedOperationException();

            }

            @Override
            public void fulfillAfterFilters(RequestBinderRegistry requestBinderRegistry, HttpRequest request) {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean isFulfilled() {
                return false;
            }

            @Override
            public Optional<Argument<?>> getRequiredInput(String name) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Object execute() {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean isSatisfied(String name) {
                throw new UnsupportedOperationException();
            }
        };
    }
}