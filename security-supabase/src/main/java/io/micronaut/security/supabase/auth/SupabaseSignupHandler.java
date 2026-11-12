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
package io.micronaut.security.supabase.auth;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.security.config.ServerContextPathProviderUtils;
import io.micronaut.security.config.SignupRedirectConfiguration;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.handlers.RedirectingLoginHandler;
import io.micronaut.security.handlers.SignupHandler;
import io.micronaut.supabase.auth.SignupRequest;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.Map;

/**
 * Creates users with Supabase Auth's {@code POST /signup}.
 *
 * <p>The signup body is read for the {@code email}, {@code phone}, {@code password}, {@code channel} and
 * {@code data} fields of a {@link SignupRequest}; other fields are ignored.</p>
 *
 * <p>The response follows the login handler of the application, so that signup and login answer alike:</p>
 * <ul>
 *   <li>When the login handler is a {@link RedirectingLoginHandler}, as in the {@code cookie}, {@code idtoken}
 *   and {@code session} authentication modes, and {@code micronaut.security.redirect.enabled} is not
 *   {@code false}, the handler answers {@code 303 See Other} to {@code micronaut.security.redirect.signup.success}
 *   or {@code micronaut.security.redirect.signup.failure}. This suits HTML signup forms. The user is not signed in:
 *   signing in stays the job of the login endpoint.</li>
 *   <li>Otherwise, as in the {@code bearer} authentication mode, the handler relays the Supabase status and JSON
 *   body: the session, or the user alone when email confirmation is required, on success, and the error, for
 *   example {@code 422} with the {@code error_code} {@code user_already_exists} or {@code weak_password}, on
 *   failure.</li>
 * </ul>
 *
 * <p>The handler calls Supabase with the blocking HTTP client and therefore must run on the
 * {@link io.micronaut.scheduling.TaskExecutors#BLOCKING} executor, as
 * {@link io.micronaut.security.endpoints.SignupController} does.</p>
 *
 * @since 0.0.1
 */
@Experimental
@Requires(classes = HttpRequest.class)
@Requires(beans = SupabaseAuthClient.class)
@Singleton
public class SupabaseSignupHandler implements SignupHandler<HttpRequest<?>, HttpResponse<?>> {
    /**
     * Signup body field holding the email address.
     */
    public static final String EMAIL = "email";

    /**
     * Signup body field holding the phone number.
     */
    public static final String PHONE = "phone";

    /**
     * Signup body field holding the password.
     */
    public static final String PASSWORD = "password";

    /**
     * Signup body field holding the channel, {@code sms} or {@code whatsapp}, of a phone signup.
     */
    public static final String CHANNEL = "channel";

    /**
     * Signup body field holding the user metadata.
     */
    public static final String DATA = "data";

    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);

    private final SupabaseAuthClient client;

    @Nullable
    private final URI signupSuccess;

    @Nullable
    private final URI signupFailure;

    /**
     * Creates the handler.
     *
     * @param client Supabase Auth client
     * @param redirectConfiguration Redirect configuration
     * @param signupRedirectConfiguration Signup redirect URLs
     * @param serverContextPathProvider Server context path, prepended to the signup redirect URLs
     * @param loginHandler Login handler of the application, whose kind decides between redirects and JSON responses
     */
    public SupabaseSignupHandler(SupabaseAuthClient client,
                                 RedirectConfiguration redirectConfiguration,
                                 SignupRedirectConfiguration signupRedirectConfiguration,
                                 @Nullable ServerContextPathProvider serverContextPathProvider,
                                 @Nullable LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler) {
        this.client = client;
        boolean redirect = loginHandler instanceof RedirectingLoginHandler && redirectConfiguration.isEnabled();
        this.signupSuccess = redirect ? redirectUri(signupRedirectConfiguration.getSuccess(), serverContextPathProvider) : null;
        this.signupFailure = redirect ? redirectUri(signupRedirectConfiguration.getFailure(), serverContextPathProvider) : null;
    }

    @Override
    public HttpResponse<?> signup(HttpRequest<?> request, Map<String, Object> body) {
        HttpResponse<Map<String, Object>> response;
        try {
            response = client.signup(null, signupRequest(body));
        } catch (HttpClientResponseException e) {
            return signupFailed(request, e);
        }
        if (response.getStatus().getCode() >= 400) {
            return signupFailed(request, new HttpClientResponseException(response.reason(), response));
        }
        return signupSuccess(request, response);
    }

    /**
     * Maps a signup body to a Supabase Auth signup request.
     *
     * @param body Signup body
     * @return The signup request
     */
    @NonNull
    protected SignupRequest signupRequest(@NonNull Map<String, Object> body) {
        return new SignupRequest(string(body, EMAIL), string(body, PHONE), string(body, PASSWORD),
            string(body, CHANNEL), data(body), null, null, null);
    }

    /**
     * Builds the response to a signup Supabase accepted.
     *
     * @param request Signup request
     * @param response Supabase response: the session, or the user alone when email confirmation is required
     * @return A redirect to the signup success URL, or the Supabase status and body
     */
    @NonNull
    protected HttpResponse<?> signupSuccess(@NonNull HttpRequest<?> request,
                                            @NonNull HttpResponse<Map<String, Object>> response) {
        if (signupSuccess != null) {
            return HttpResponse.seeOther(signupSuccess);
        }
        return HttpResponse.status(response.getStatus()).body(response.body());
    }

    /**
     * Builds the response to a signup Supabase rejected.
     *
     * @param request Signup request
     * @param e Supabase rejection, whose response carries the Supabase status and error body
     * @return A redirect to the signup failure URL, or the Supabase status and error body
     */
    @NonNull
    protected HttpResponse<?> signupFailed(@NonNull HttpRequest<?> request, @NonNull HttpClientResponseException e) {
        if (signupFailure != null) {
            return HttpResponse.seeOther(signupFailure);
        }
        return HttpResponse.status(e.getStatus()).body(e.getResponse().getBody(MAP_ARGUMENT).orElse(null));
    }

    @NonNull
    private static URI redirectUri(@NonNull String url, @Nullable ServerContextPathProvider serverContextPathProvider) {
        return URI.create(serverContextPathProvider == null
            ? url
            : ServerContextPathProviderUtils.prependContextPath(url, serverContextPathProvider));
    }

    @Nullable
    private static String string(@NonNull Map<String, Object> body, @NonNull String name) {
        return body.get(name) instanceof CharSequence value ? value.toString() : null;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    private static Map<String, Object> data(@NonNull Map<String, Object> body) {
        return body.get(DATA) instanceof Map<?, ?> data ? (Map<String, Object>) data : null;
    }
}
