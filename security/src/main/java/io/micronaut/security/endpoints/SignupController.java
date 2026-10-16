package io.micronaut.security.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.handlers.SignupHandler;
import io.micronaut.security.rules.SecurityRule;

import java.util.Map;

@Requires(property = SignupControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(classes = Controller.class)
@Requires(beans = { SignupHandler.class })
@Controller("${" + SignupControllerConfigurationProperties.PREFIX + ".path:/logout}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class SignupController {

    private final SignupHandler<HttpRequest<?>, HttpResponse<?>> signupHandler;

    public SignupController(SignupHandler<HttpRequest<?>, HttpResponse<?>> signupHandler) {
        this.signupHandler = signupHandler;
    }

    @Post
    HttpResponse<?> signup(HttpRequest<?> request, @Body Map<String, Object> body) {
        return signupHandler.signup(request, body);
    }
}
