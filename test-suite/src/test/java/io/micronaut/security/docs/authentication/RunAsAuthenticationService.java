package io.micronaut.security.docs.authentication;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.annotation.RunAsAuthentication;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.SecurityContextHolder;
import jakarta.inject.Singleton;

@Requires(property = "spec.name", value = "RunAsAuthenticationTest")
//tag::clazz[]
@RunAsAuthentication("""
            {"name":"aegon","attributes":{"family_name":"Targaryen","roles":["ROLE_KING"]}}""")
@Singleton
public class RunAsAuthenticationService {
    public Authentication changeAuth() {
        return SecurityContextHolder.getSecurityContext().getAuthentication();
    }
}
//end::clazz[]
