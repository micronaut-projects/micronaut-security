package io.micronaut.docs.rejection;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.authentication.DefaultAuthorizationExceptionHandler;

import javax.inject.Singleton;

@Requires(property = "spec.name", value = "rejection-handler")
//tag::clazz[]
@Singleton
@Replaces(DefaultAuthorizationExceptionHandler.class)
public class MyRejectionHandler extends DefaultAuthorizationExceptionHandler {

    @Override
    public MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        //Let the HttpStatusCodeRejectionHandler create the initial request
        //then add a header
        return super.handle(request, exception).header("X-Reason", "Example Header");
    }
}
//end::clazz[]
