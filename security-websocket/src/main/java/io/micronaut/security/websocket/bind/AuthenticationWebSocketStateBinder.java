package io.micronaut.security.websocket.bind;

import io.micronaut.core.bind.ArgumentBinder;
import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.websocket.bind.WebSocketState;
import io.micronaut.websocket.bind.WebSocketStateBinder;
import jakarta.inject.Singleton;

import java.security.Principal;
import java.util.Optional;

@Singleton
public final class AuthenticationWebSocketStateBinder implements WebSocketStateBinder<Authentication> {

    @Override
    public ArgumentBinder.BindingResult<Authentication> bind(
        ArgumentConversionContext<Authentication> context,
        WebSocketState source) {

        Optional<Principal> principal = source.getOriginatingRequest().getUserPrincipal();
        if (principal.isEmpty()) {
            principal = source.getSession().getUserPrincipal();
        }

        if (principal.isPresent() && principal.get() instanceof Authentication auth) {
            return () -> Optional.of(auth);
        }
        return Optional::empty;
    }
}
