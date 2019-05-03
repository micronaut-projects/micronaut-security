package io.micronaut.security.oauth2.routes;

import io.micronaut.context.annotation.Executable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.rules.SecurityRule;
import org.reactivestreams.Publisher;

import java.util.Map;

@Secured(SecurityRule.IS_ANONYMOUS)
public interface OauthController {

    OauthClient getClient();

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Executable
    HttpResponse logout(HttpRequest request, Authentication authentication);

    @Executable
    Publisher<HttpResponse> login(HttpRequest request);

    @Executable
    Publisher<HttpResponse> callback(HttpRequest<Map<String, Object>> request);

}
