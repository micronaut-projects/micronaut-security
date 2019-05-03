package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

import javax.inject.Singleton;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Singleton
public class DefaultOpenIdUserDetailsMapper implements OpenIdUserDetailsMapper {

    @Override
    public UserDetails createUserDetails(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        Map<String, Object> claims = new HashMap<>(openIdClaims.getClaims());
        JwtClaims.ALL_CLAIMS.forEach(claims::remove);
        claims.put("openIdToken", tokenResponse.getIdToken());
        claims.put(OauthUserDetailsMapper.PROVIDER_KEY, providerName);
        return new UserDetails(openIdClaims.getSubject(), Collections.emptyList(), claims);
    }

}
