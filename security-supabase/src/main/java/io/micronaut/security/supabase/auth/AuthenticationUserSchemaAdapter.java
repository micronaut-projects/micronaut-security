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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.supabase.auth.UserSchema;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Adapter from {@link UserSchema} to {@link Authentication}.
 *
 * <p>The authentication name is the user id, which is also the {@code sub} claim of the user's tokens. The
 * attributes are the user's non-null fields keyed by their JSON names, such as {@code email},
 * {@code app_metadata} or {@code is_anonymous}, mirroring the claims Supabase places in its access tokens.
 * The Supabase {@code role}, typically {@code authenticated}, is exposed as the single Micronaut role.</p>
 *
 * @since 0.0.1
 */
@Experimental
public class AuthenticationUserSchemaAdapter implements Authentication {
    /**
     * Adapted user; {@code null} yields an authentication without name, attributes or roles.
     */
    @Nullable
    private final UserSchema user;

    /**
     * Creates the adapter.
     *
     * @param user Supabase Auth user, as returned by {@code GET /user} or embedded in a token response
     */
    public AuthenticationUserSchemaAdapter(@Nullable UserSchema user) {
        this.user = user;
    }

    /**
     * Returns the adapted user, for callers that need typed access beyond the attribute map.
     *
     * @return The adapted user, or {@code null}
     */
    @Nullable
    public UserSchema getUser() {
        return user;
    }

    @Override
    @NonNull
    public Map<String, Object> getAttributes() {
        if (user == null) {
            return Collections.emptyMap();
        }
        Map<String, Object> attributes = new LinkedHashMap<>();
        put(attributes, "id", user.id());
        put(attributes, "aud", user.aud());
        put(attributes, "role", user.role());
        put(attributes, "email", user.email());
        put(attributes, "email_confirmed_at", user.emailConfirmedAt());
        put(attributes, "phone", user.phone());
        put(attributes, "phone_confirmed_at", user.phoneConfirmedAt());
        put(attributes, "confirmation_sent_at", user.confirmationSentAt());
        put(attributes, "confirmed_at", user.confirmedAt());
        put(attributes, "recovery_sent_at", user.recoverySentAt());
        put(attributes, "new_email", user.newEmail());
        put(attributes, "email_change_sent_at", user.emailChangeSentAt());
        put(attributes, "new_phone", user.newPhone());
        put(attributes, "phone_change_sent_at", user.phoneChangeSentAt());
        put(attributes, "reauthentication_sent_at", user.reauthenticationSentAt());
        put(attributes, "last_sign_in_at", user.lastSignInAt());
        put(attributes, "app_metadata", user.appMetadata());
        put(attributes, "user_metadata", user.userMetadata());
        put(attributes, "factors", user.factors());
        put(attributes, "identities", user.identities());
        put(attributes, "banned_until", user.bannedUntil());
        put(attributes, "created_at", user.createdAt());
        put(attributes, "updated_at", user.updatedAt());
        put(attributes, "deleted_at", user.deletedAt());
        put(attributes, "is_anonymous", user.isAnonymous());
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    @NonNull
    public Collection<String> getRoles() {
        return user == null || user.role() == null ? Collections.emptyList() : List.of(user.role());
    }

    @Override
    @Nullable
    public String getName() {
        return user == null ? null : user.id();
    }

    private static void put(Map<String, Object> attributes, String name, @Nullable Object value) {
        if (value != null) {
            attributes.put(name, value);
        }
    }
}
