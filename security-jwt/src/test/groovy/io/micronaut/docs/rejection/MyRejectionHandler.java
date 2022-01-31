package io.micronaut.docs.rejection;

//tag::clazz[]
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.server.exceptions.response.ErrorResponseProcessor;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.authentication.DefaultAuthorizationExceptionHandler;

import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.errors.PriorToLoginPersistence;
import jakarta.inject.Singleton;

//end::clazz[]

@Requires(property = "spec.name", value = "rejection-handler")
//tag::clazz[]
@Singleton
@Replaces(DefaultAuthorizationExceptionHandler.class)
public class MyRejectionHandler extends DefaultAuthorizationExceptionHandler {

    public MyRejectionHandler(
            RedirectConfiguration redirectConfiguration,
            @Nullable PriorToLoginPersistence priorToLoginPersistence,
            @Nullable ErrorResponseProcessor<?> responseProcessor
    ) {
        super(redirectConfiguration, priorToLoginPersistence, responseProcessor);
    }

    @Override
    public MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        //Let the DefaultAuthorizationExceptionHandler create the initial response
        //then add a header
        return super.handle(request, exception).header("X-Reason", "Example Header");
    }
}
//end::clazz[]
