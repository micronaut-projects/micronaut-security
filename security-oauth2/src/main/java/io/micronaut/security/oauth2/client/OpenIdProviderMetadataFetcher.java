package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.context.Qualifier;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Optional;

@Singleton
public class OpenIdProviderMetadataFetcher {
    private static final Logger LOG = LoggerFactory.getLogger(OpenIdClientFactory.class);

    private final BeanContext beanContext;
    private final HttpClientConfiguration defaultHttpConfiguration;

    public OpenIdProviderMetadataFetcher(BeanContext beanContext,
                                         HttpClientConfiguration defaultHttpConfiguration) {
        this.beanContext = beanContext;
        this.defaultHttpConfiguration = defaultHttpConfiguration;
    }

    /**
     *
     * @param qualifier The qualifier
     * @return The OpenIdProviderMetadata bean for the supplied qualifier if one exist, or a newly created. If the bean context does not contain {@link OpenIdClientConfiguration} or {@link OauthClientConfiguration} for the supplied qualifier an empty is returned.
     */
    public Optional<OpenIdProviderMetadata> fetchOpenIdProviderMetadataByQualifier(Qualifier qualifier) {
        if (beanContext.containsBean(OpenIdProviderMetadata.class, qualifier)) {
            return Optional.of(beanContext.getBean(OpenIdProviderMetadata.class, qualifier));
        }
        if (!beanContext.containsBean(OpenIdClientConfiguration.class, qualifier)) {
            return Optional.empty();
        }
        if (!beanContext.containsBean(OauthClientConfiguration.class, qualifier)) {
            return Optional.empty();
        }
        OauthClientConfiguration oauthClientConfiguration = beanContext.getBean(OauthClientConfiguration.class, qualifier);
        OpenIdClientConfiguration openIdClientConfiguration = beanContext.getBean(OpenIdClientConfiguration.class, qualifier);
        OpenIdProviderMetadata openIdProviderMetadata = fetchOpenIdProviderMetadata(oauthClientConfiguration, openIdClientConfiguration);

        beanContext.registerSingleton(OpenIdProviderMetadata.class, openIdProviderMetadata, qualifier);

        return Optional.of(openIdProviderMetadata);
    }

    private OpenIdProviderMetadata fetchOpenIdProviderMetadata(OauthClientConfiguration oauthClientConfiguration,
                                                               OpenIdClientConfiguration openIdClientConfiguration) {
        DefaultOpenIdProviderMetadata providerMetadata = openIdClientConfiguration.getIssuer()
                .map(issuer -> {
                    RxHttpClient issuerClient = null;
                    try {
                        URL configurationUrl = new URL(issuer, StringUtils.prependUri(issuer.getPath(), openIdClientConfiguration.getConfigurationPath()));
                        issuerClient = beanContext.createBean(RxHttpClient.class, LoadBalancer.empty(), defaultHttpConfiguration);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Sending request for OpenID configuration for provider [{}] to URL [{}]", openIdClientConfiguration.getName(), configurationUrl);
                        }
                        return issuerClient.toBlocking().retrieve(configurationUrl.toString(), DefaultOpenIdProviderMetadata.class);
                    } catch (HttpClientResponseException e) {
                        throw new BeanInstantiationException("Failed to retrieve OpenID configuration for " + openIdClientConfiguration.getName(), e);
                    } catch (MalformedURLException e) {
                        throw new BeanInstantiationException("Failure parsing issuer URL " + issuer.toString(), e);
                    } finally {
                        if (issuerClient != null) {
                            issuerClient.stop();
                        }
                    }
                }).orElse(new DefaultOpenIdProviderMetadata());

        overrideFromConfig(providerMetadata, openIdClientConfiguration, oauthClientConfiguration);
        return providerMetadata;
    }

    private void overrideFromConfig(DefaultOpenIdProviderMetadata configuration,
                                    OpenIdClientConfiguration openIdClientConfiguration,
                                    OauthClientConfiguration oauthClientConfiguration) {
        openIdClientConfiguration.getJwksUri().ifPresent(configuration::setJwksUri);

        oauthClientConfiguration.getIntrospection().ifPresent(introspection -> {
            introspection.getUrl().ifPresent(configuration::setIntrospectionEndpoint);
            introspection.getAuthMethod().ifPresent(authMethod -> configuration.setIntrospectionEndpointAuthMethodsSupported(Collections.singletonList(authMethod.toString())));
        });
        oauthClientConfiguration.getRevocation().ifPresent(revocation -> {
            revocation.getUrl().ifPresent(configuration::setRevocationEndpoint);
            revocation.getAuthMethod().ifPresent(authMethod -> configuration.setRevocationEndpointAuthMethodsSupported(Collections.singletonList(authMethod.toString())));
        });

        openIdClientConfiguration.getRegistration()
                .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setRegistrationEndpoint);
        openIdClientConfiguration.getUserInfo()
                .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setUserinfoEndpoint);
        openIdClientConfiguration.getAuthorization()
                .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setAuthorizationEndpoint);
        openIdClientConfiguration.getToken().ifPresent(token -> {
            token.getUrl().ifPresent(configuration::setTokenEndpoint);
            token.getAuthMethod().ifPresent(authMethod -> configuration.setTokenEndpointAuthMethodsSupported(Collections.singletonList(authMethod.toString())));
        });

        EndSessionEndpointConfiguration endSession = openIdClientConfiguration.getEndSession();
        if (endSession.isEnabled()) {
            endSession.getUrl().ifPresent(configuration::setEndSessionEndpoint);
        }
    }
}
