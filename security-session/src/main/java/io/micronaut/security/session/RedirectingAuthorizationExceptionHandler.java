package io.micronaut.security.session;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.http.*;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.authentication.HttpStatusAuthorizationExceptionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;

@Singleton
@Replaces(HttpStatusAuthorizationExceptionHandler.class)
public class RedirectingAuthorizationExceptionHandler extends HttpStatusAuthorizationExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(RedirectingAuthorizationExceptionHandler.class);

    private final SecuritySessionConfiguration configuration;

    RedirectingAuthorizationExceptionHandler(SecuritySessionConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public HttpResponse handle(HttpRequest request, AuthorizationException exception) {
        if (shouldHandleRequest(request)) {
            try {
                URI location = new URI(getRedirectUri(request, exception));
                //prevent redirect loop
                if (!request.getUri().equals(location)) {
                    return httpResponseWithUri(location);
                } else {
                    return super.handle(request, exception);
                }
            } catch (URISyntaxException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Rejection redirect URL is invalid", e);
                }
                return HttpResponse.serverError();
            }
        } else {
            return super.handle(request, exception);
        }
    }

    /**
     * Decides whether the request should be handled with a redirect.
     *
     * @param request The HTTP Request
     * @return true if the request accepts text/html
     */
    protected boolean shouldHandleRequest(HttpRequest<?> request) {
        return configuration.isRedirectOnRejection() && request.getHeaders()
                .accept()
                .stream()
                .anyMatch(mediaType -> mediaType.equals(MediaType.TEXT_HTML_TYPE));
    }

    protected String getRedirectUri(HttpRequest<?> request, AuthorizationException exception) {
        String uri = exception.isForbidden() ? configuration.getForbiddenTargetUrl() :
                configuration.getUnauthorizedTargetUrl();
        if (LOG.isDebugEnabled()) {
            LOG.debug("redirect uri: {}", uri);
        }
        return uri;
    }

    /**
     * Builds a HTTP Response redirection to the supplied location.
     *
     * @param location The Uri to redirect to
     * @return an HTTP response with the Uri as location
     */
    protected MutableHttpResponse<?> httpResponseWithUri(URI location) {
        return HttpResponse.status(HttpStatus.SEE_OTHER)
                .headers((headers) ->
                        headers.location(location)
                );
    }
}
