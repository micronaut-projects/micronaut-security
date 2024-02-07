package io.micronaut.security.jacksondatabind.beanintrospectionfalse;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Property(name = "jackson.bean-introspection-module", value = StringUtils.FALSE)
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "spec.name", value = "UsernamePasswordCredentialsBeanIntrospectionModuleFalseTest")
@MicronautTest
class UsernamePasswordCredentialsBeanIntrospectionModuleFalseTest {

    @Test
    void testUsernamePasswordCredentialsDeserializationIfBeanIntrospectionModuleFalse(@Client("/")HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        String json = """
                {"username":"sherlock","password":"password"}""";
        assertDoesNotThrow(() -> client.exchange(HttpRequest.POST("/login", json)));
    }

    @Requires(property = "spec.name", value = "UsernamePasswordCredentialsBeanIntrospectionModuleFalseTest")
    @Singleton
    static class CustomAuthenticationProvider<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }
}
