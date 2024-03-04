package io.micronaut.security.authentication;

import io.micronaut.core.annotation.Internal;

import java.util.Comparator;

@Internal
final class AuthenticationResponseComparator implements Comparator<AuthenticationResponse> {
    @Override
    public int compare(AuthenticationResponse o1, AuthenticationResponse o2) {
        if (o1.isAuthenticated() && !o2.isAuthenticated()) {
            return -1;
        } else if (!o1.isAuthenticated() && o2.isAuthenticated()) {
            return 1;
        }
        return 0;
    }
}
