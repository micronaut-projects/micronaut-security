/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.exceptions.UriSyntaxException;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.function.Supplier;

/**
 * A base class to extend from to log out of an OpenID provider.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public abstract class AbstractEndSessionRequest implements EndSessionEndpoint {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractEndSessionRequest.class);
    private static final int MAX_LOGGED_URL_LENGTH = 200;

    protected final EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder;
    protected final OauthClientConfiguration clientConfiguration;
    protected final Supplier<OpenIdProviderMetadata> providerMetadataSupplier;

    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata supplier
     */
    public AbstractEndSessionRequest(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                     OauthClientConfiguration clientConfiguration,
                                     Supplier<OpenIdProviderMetadata> providerMetadata) {
        this.endSessionCallbackUrlBuilder = endSessionCallbackUrlBuilder;
        this.clientConfiguration = clientConfiguration;
        this.providerMetadataSupplier = providerMetadata;
    }

    /**
     * Builds the end session redirect URL by appending the {@link #getArguments(HttpRequest, Authentication)} to the
     * query component of {@link #getUrl()}. The end session URL is treated as an opaque URI, never as a URI template,
     * so a provider cannot influence how the parameters are rendered. Argument values are percent-encoded. A
     * {@code null} argument value is skipped and an {@link Iterable} or array value is rendered as a repeated
     * parameter. The end session URL must be an absolute {@code http} or {@code https} URL with a host; a relative URL,
     * another scheme or an authority component carrying user information ({@code https://user:password@host/...}) is
     * rejected, since an end session endpoint never legitimately takes those forms.
     *
     * @param originating The originating request
     * @param authentication The authentication
     * @return The end session URL, or {@code null} if {@link #getUrl()} is empty, is not an absolute http(s) URL with a
     * host and without user information, or is not a valid URI
     */
    @Nullable
    @Override
    public String getUrl(HttpRequest<?> originating, Authentication authentication) {
        String endSessionUrl = getUrl();
        if (StringUtils.isEmpty(endSessionUrl)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("No end session URL is available; skipping end session redirect");
            }
            return null;
        }
        if (!hasValidAuthority(endSessionUrl)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("End session URL [{}] is not an absolute http(s) URL with a host and without user information; skipping end session redirect", abbreviate(endSessionUrl));
            }
            return null;
        }
        Map<String, Object> arguments = getArguments(originating, authentication);
        try {
            // The authority has been validated above and is passed through verbatim: UriBuilder would percent-encode
            // an IPv6 literal host. Only the path, query and fragment go through the builder.
            int authorityEnd = authorityEnd(endSessionUrl);
            UriBuilder builder = UriBuilder.of(endSessionUrl.substring(authorityEnd));
            if (arguments != null) {
                for (Map.Entry<String, Object> entry : arguments.entrySet()) {
                    addQueryParam(builder, entry.getKey(), entry.getValue());
                }
            }
            return endSessionUrl.substring(0, authorityEnd) + builder.build();
        } catch (UriSyntaxException | IllegalArgumentException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("End session URL [{}] is not a valid URI; skipping end session redirect", abbreviate(endSessionUrl));
            }
            return null;
        }
    }

    /**
     * @param url A URL
     * @return Whether the URL is an absolute {@code http} or {@code https} URL whose authority component has a host
     * and no user information
     */
    private static boolean hasValidAuthority(String url) {
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            return false;
        }
        String scheme = url.substring(0, schemeEnd);
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            return false;
        }
        int authorityStart = schemeEnd + 3;
        String authority = url.substring(authorityStart, authorityEnd(url));
        if (authority.isEmpty() || authority.indexOf('@') >= 0) {
            return false;
        }
        try {
            URI probe = new URI("http://" + authority + "/");
            return probe.getRawUserInfo() == null && probe.getHost() != null && authority.equals(probe.getRawAuthority());
        } catch (URISyntaxException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * @param url An absolute URL with an authority component
     * @return The index at which the path, query or fragment following the authority starts, or the length of the
     * URL if it has none
     */
    private static int authorityEnd(String url) {
        int authorityStart = url.indexOf("://") + 3;
        int authorityEnd = url.length();
        for (char delimiter : new char[] {'/', '?', '#'}) {
            int index = url.indexOf(delimiter, authorityStart);
            if (index >= 0 && index < authorityEnd) {
                authorityEnd = index;
            }
        }
        return authorityEnd;
    }

    private static String abbreviate(String url) {
        if (url.length() <= MAX_LOGGED_URL_LENGTH) {
            return url;
        }
        return url.substring(0, MAX_LOGGED_URL_LENGTH) + "... (" + url.length() + " characters)";
    }

    private static void addQueryParam(UriBuilder builder, String name, @Nullable Object value) {
        if (name == null || value == null) {
            return;
        }
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                if (item != null) {
                    builder.queryParam(name, item);
                }
            }
        } else if (value instanceof Object[] array) {
            for (Object item : array) {
                if (item != null) {
                    builder.queryParam(name, item);
                }
            }
        } else {
            builder.queryParam(name, value);
        }
    }

    /**
     * @return The url of the request
     */
    protected abstract String getUrl();

    /**
     * @param originating The originating request
     * @param authentication The authentication
     * @return The parameters to include in the URL
     */
    protected abstract Map<String, Object> getArguments(HttpRequest<?> originating, Authentication authentication);

    /**
     * @param originating The originating request
     * @return The absolute redirect URI
     */
    protected String getRedirectUri(HttpRequest<?> originating) {
        return endSessionCallbackUrlBuilder.build(originating).toString();
    }
}
