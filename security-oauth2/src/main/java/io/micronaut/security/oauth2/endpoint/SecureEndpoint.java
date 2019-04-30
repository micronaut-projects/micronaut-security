package io.micronaut.security.oauth2.endpoint;

import java.util.List;
import java.util.Optional;

public interface SecureEndpoint extends Endpoint {

    Optional<List<AuthenticationMethod>> getSupportedAuthenticationMethods();
}
