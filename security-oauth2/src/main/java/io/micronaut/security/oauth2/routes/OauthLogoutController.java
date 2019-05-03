package io.micronaut.security.oauth2.routes;

import io.micronaut.context.BeanContext;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionRequest;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.micronaut.security.rules.SecurityRule;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

@Controller("${micronaut.security.oauth2.logout-path:/oauth/logout}")
public class OauthLogoutController {

    private final BeanContext beanContext;

    /**
     *
     * @param beanContext the Bean context
     */
    public OauthLogoutController(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Get
    public Publisher<HttpResponse> logout(HttpRequest<?> request, Authentication authentication) {
        Object provider = authentication.getAttributes().get(OauthUserDetailsMapper.PROVIDER_KEY);
        if (provider != null) {
            return Flowable.just(beanContext.findBean(EndSessionRequest.class, Qualifiers.byName(provider.toString())).map(endSessionRequest -> {
                String url = endSessionRequest.getUrl(request, authentication);
                return HttpResponse.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, url);
            }).orElseGet(HttpResponse::notFound));
        } else {
            return Flowable.just(HttpResponse.notFound());
        }
    }
}
