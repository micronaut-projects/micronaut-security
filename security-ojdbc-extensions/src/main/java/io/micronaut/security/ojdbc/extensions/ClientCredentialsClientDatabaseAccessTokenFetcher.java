/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.ojdbc.extensions;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import oracle.jdbc.spi.OracleResourceProvider;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.CLIENT_ID_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.CLIENT_SECRET_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.SCOPE_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.TOKEN_URL_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.OracleResourceProviderParameterUtils.optionalParameter;
import static io.micronaut.security.ojdbc.extensions.OracleResourceProviderParameterUtils.requiredParameter;

/**
 * Fetches Oracle Database access tokens with the OAuth 2.0 Client Credentials flow.
 *
 * @since 5.1.0
 */
@Experimental
@Internal
class ClientCredentialsClientDatabaseAccessTokenFetcher implements DatabaseAccessTokenFetcher {
    private final Map<String, HttpClient> httpClientMap = new ConcurrentHashMap<>();
    private final Map<ClientCredentialsClientConfiguration, ClientCredentialsClient> clientCredentialsClientMap = new ConcurrentHashMap<>();

    /**
     * Creates a database access token fetcher.
     *
     * @since 5.1.0
     */
    ClientCredentialsClientDatabaseAccessTokenFetcher() {
    }

    /**
     * This implementation reads the OAuth 2.0 client credentials parameters
     * supplied by OJDBC and requests a database access token from the configured
     * token endpoint.
     *
     * @param parameters parameters supplied to the OJDBC resource provider
     * @return a database access token
     * @throws DatabaseAccessTokenFetcherException if a database access token cannot be obtained
     * @since 5.1.0
     */
    @Override
    public @NonNull String fetchDatabaseAccessToken(@NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters) {
        try {
            String tokenUrl = requiredParameter(parameters, TOKEN_URL_PARAMETER);
            String clientId = requiredParameter(parameters, CLIENT_ID_PARAMETER);
            String clientSecret = requiredParameter(parameters, CLIENT_SECRET_PARAMETER);
            String scope = optionalParameter(parameters, SCOPE_PARAMETER);
            return fetchDatabaseAccessToken(tokenUrl, clientId, clientSecret, scope);
        } catch (IllegalStateException e) {
            throw new DatabaseAccessTokenFetcherException(e.getMessage(), e);
        }
    }

    /**
     * This implementation requests and validates an OAuth 2.0 access token for
     * the supplied client credentials.
     *
     * @param tokenUrl token endpoint URL
     * @param clientId client identifier
     * @param clientSecret client secret
     * @param scope optional token scope
     * @return a database access token
     */
    final @NonNull String fetchDatabaseAccessToken(@NonNull String tokenUrl,
                                                   @NonNull String clientId,
                                                   @NonNull String clientSecret,
                                                   @Nullable String scope) {
        String normalizedScope = normalizeScope(scope);
        try {
            ClientCredentialsClient client = clientCredentialsClient(tokenUrl, clientId, clientSecret, normalizedScope);
            TokenResponse tokenResponse = Mono.from(client.requestToken(normalizedScope)).block();
            if (tokenResponse == null || StringUtils.isEmpty(tokenResponse.getAccessToken())) {
                throw new DatabaseAccessTokenFetcherException("Token endpoint response did not contain access_token");
            }
            return tokenResponse.getAccessToken();
        } catch (HttpClientResponseException e) {
            int statusCode = e.getStatus().getCode();
            if (statusCode >= 400) {
                throw new DatabaseAccessTokenFetcherException("Token endpoint returned HTTP status "
                        + statusCode + ": " + e.getMessage(), e);
            }
            throw new DatabaseAccessTokenFetcherException("Failed to request database access token", e);
        } catch (RuntimeException e) {
            if (Exceptions.unwrap(e) instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                throw new DatabaseAccessTokenFetcherException("Interrupted while requesting database access token", e);
            }
            throw new DatabaseAccessTokenFetcherException("Failed to request database access token", e);
        }
    }

    private ClientCredentialsClient  clientCredentialsClient(@NonNull String tokenUrl,
                                                              @NonNull String clientId,
                                                              @NonNull String clientSecret,
                                                              @Nullable String scope) {
        ClientCredentialsClientConfiguration clientCredentialsClientConfiguration = new ClientCredentialsClientConfiguration(tokenUrl, clientId, clientSecret, scope);
        return clientCredentialsClientMap.computeIfAbsent(clientCredentialsClientConfiguration, k -> {
            HttpClient httpClient = oauthClientCredentialsHttpClient(k);
            return ClientCredentialsClient.of(httpClient, oauthClientConfiguration(k));
        });
    }

    private HttpClient oauthClientCredentialsHttpClient(ClientCredentialsClientConfiguration k) {
        return httpClientMap.computeIfAbsent(k.tokenUrl(), key -> {
            try {
                return HttpClient.create(new URL(key));
            } catch (MalformedURLException e) {
                throw new ConfigurationException("token URL " + k + " is invalid", e);
            }
        });
    }

    private OauthClientConfiguration oauthClientConfiguration(ClientCredentialsClientConfiguration k) {
        OauthClientConfigurationBuilder builder = OauthClientConfiguration.builder()
                .name("end-security-context-provider")
                .token(k.tokenUrl())
                .clientId(k.clientId())
                .clientSecret(k.clientSecret());
        if (k.scope() != null) {
            builder.scopes(k.scope());
        }
        return builder.build();
    }

    @Nullable
    private static String normalizeScope(@Nullable String scope) {
        return scope == null || scope.isBlank() ? null : scope;
    }

    record ClientCredentialsClientConfiguration(@NonNull String tokenUrl,
                                                @NonNull String clientId,
                                                @NonNull String clientSecret,
                                                @Nullable String scope) {
    }
}
