package io.micronaut.security.oauth2.endpoint.authorization.request;

import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.core.async.SupplierUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.function.Supplier;

@Prototype
public class DefaultOauthAuthorizationRequest implements OauthAuthorizationRequest {

    private final HttpRequest<?> request;
    private final OauthClientConfiguration oauthClientConfiguration;
    private final CallbackUrlBuilder callbackUrlBuilder;
    private final Supplier<String> stateSupplier;


    DefaultOauthAuthorizationRequest(@Parameter HttpRequest<?> request,
                                     @Parameter OauthClientConfiguration oauthClientConfiguration,
                                     CallbackUrlBuilder callbackUrlBuilder,
                                     @Nullable StateFactory stateFactory) {
        this.request = request;
        this.oauthClientConfiguration = oauthClientConfiguration;
        this.callbackUrlBuilder = callbackUrlBuilder;
        this.stateSupplier = SupplierUtil.memoized(() -> {
            if (stateFactory != null) {
                return stateFactory.buildState(request);
            } else {
                return null;
            }
        });

    }

    @Override
    @Nonnull
    public String getClientId() {
        return oauthClientConfiguration.getClientId();
    }

    @Override
    @Nullable
    public String getState() {
        return stateSupplier.get();
    }

    @Override
    @Nonnull
    public List<String> getScopes() {
        return oauthClientConfiguration.getScopes();
    }

    @Nonnull
    @Override
    public String getResponseType() {
        return ResponseType.CODE.toString();
    }

    @Nullable
    @Override
    public String getRedirectUri() {
        return callbackUrlBuilder.build(request, oauthClientConfiguration.getName());
    }
}
