/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.state.persistence;

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory;
import io.micronaut.session.Session;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Stores values of in-flight OAuth 2.0 login flows in a HTTP session, keyed by the nonce of the {@link State} of the
 * flow they belong to, so that several login flows (for example, two browser tabs or two providers) can coexist in the
 * same session without overwriting each other.
 *
 * <p>Values are kept under a single session attribute as a bounded, insertion-ordered {@link LinkedHashMap}
 * (which is {@link java.io.Serializable}). When more than {@link #MAX_ENTRIES} flows are in flight, the oldest entry is
 * evicted.</p>
 *
 * <p>When no state is available (state generation disabled, or a custom {@link StateFactory} that does not expose the
 * state via {@link StateFactory#REQUEST_ATTRIBUTE_STATE}) values are stored under a fallback key, which preserves the
 * previous single-flow behaviour.</p>
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Internal
public final class StateKeyedSessionValues {

    /**
     * Maximum number of in-flight login flows whose values are kept per session attribute.
     */
    public static final int MAX_ENTRIES = 5;

    private static final String FALLBACK_KEY = "";

    private StateKeyedSessionValues() {
    }

    /**
     * @param request The login request
     * @return The key under which the values of the login flow being started should be stored.
     */
    @NonNull
    public static String keyForLoginRequest(@NonNull HttpRequest<?> request) {
        return request.getAttribute(StateFactory.REQUEST_ATTRIBUTE_STATE, State.class)
            .map(State::getNonce)
            .orElse(FALLBACK_KEY);
    }

    /**
     * @param callbackState The state received in the authorization callback, if any
     * @return The key under which the values of the login flow being completed were stored, or {@code null} if unknown.
     */
    @Nullable
    public static String keyForCallbackState(@Nullable State callbackState) {
        return callbackState == null ? null : callbackState.getNonce();
    }

    /**
     * Stores a value for a login flow, evicting the oldest flow if the bound is exceeded.
     *
     * @param session The session
     * @param sessionKey The session attribute name
     * @param key The login flow key
     * @param value The value to store
     * @param <T> The value type
     */
    public static <T> void put(@NonNull Session session,
                               @NonNull String sessionKey,
                               @NonNull String key,
                               @NonNull T value) {
        synchronized (session) {
            LinkedHashMap<String, T> values = values(session, sessionKey);
            values.remove(key);
            values.put(key, value);
            Iterator<String> keys = values.keySet().iterator();
            while (values.size() > MAX_ENTRIES && keys.hasNext()) {
                keys.next();
                keys.remove();
            }
            session.put(sessionKey, values);
        }
    }

    /**
     * Retrieves and removes the value stored for a login flow. If {@code key} is {@code null}, or no value is stored
     * under it but a value was stored without a state (see {@link #keyForLoginRequest(HttpRequest)}), the most recently
     * stored value is returned instead, which matches the previous single-flow behaviour.
     *
     * @param session The session
     * @param sessionKey The session attribute name
     * @param key The login flow key, if known
     * @param <T> The value type
     * @return The value stored for the flow, if any
     */
    @NonNull
    public static <T> Optional<T> remove(@NonNull Session session,
                                         @NonNull String sessionKey,
                                         @Nullable String key) {
        synchronized (session) {
            LinkedHashMap<String, T> values = values(session, sessionKey);
            T value = null;
            if (key != null && values.containsKey(key)) {
                value = values.remove(key);
            } else if (values.containsKey(FALLBACK_KEY)) {
                value = values.remove(FALLBACK_KEY);
            } else if (key == null && !values.isEmpty()) {
                String lastKey = null;
                for (String k : values.keySet()) {
                    lastKey = k;
                }
                value = values.remove(lastKey);
            }
            if (values.isEmpty()) {
                session.remove(sessionKey);
            } else {
                session.put(sessionKey, values);
            }
            return Optional.ofNullable(value);
        }
    }

    @SuppressWarnings("unchecked")
    @NonNull
    private static <T> LinkedHashMap<String, T> values(@NonNull Session session, @NonNull String sessionKey) {
        Optional<Object> stored = session.get(sessionKey);
        if (stored.isPresent() && stored.get() instanceof Map<?, ?> map) {
            return new LinkedHashMap<>((Map<String, T>) map);
        }
        return new LinkedHashMap<>();
    }
}
