package io.micronaut.security.authentication;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.server.exceptions.ExceptionHandler;

import javax.inject.Singleton;

@Singleton
public class HttpStatusAuthorizationExceptionHandler implements ExceptionHandler<AuthorizationException, HttpResponse<?>> {

    @Override
    public HttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        return HttpResponse.status(exception.isForbidden() ? HttpStatus.FORBIDDEN :
                HttpStatus.UNAUTHORIZED);
    }
}
