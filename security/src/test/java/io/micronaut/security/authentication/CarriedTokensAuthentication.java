package io.micronaut.security.authentication;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Test fixture: an {@link AccessRefreshTokenAuthentication} carrying tokens issued elsewhere.
 */
public record CarriedTokensAuthentication(@Nullable String accessToken,
                                          @Nullable String refreshToken,
                                          @Nullable Integer expiresIn,
                                          @NonNull Authentication authentication) implements AccessRefreshTokenAuthentication {

    public static CarriedTokensAuthentication of(String accessToken, String refreshToken, Integer expiresIn) {
        return new CarriedTokensAuthentication(accessToken, refreshToken, expiresIn, Authentication.build("alice", java.util.List.of("ROLE_USER")));
    }

    @Override
    public @Nullable String getAccessToken() {
        return accessToken;
    }

    @Override
    public @Nullable String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public @Nullable Integer getExpiresIn() {
        return expiresIn;
    }

    @Override
    public @NonNull Authentication getAuthentication() {
        return authentication;
    }
}
