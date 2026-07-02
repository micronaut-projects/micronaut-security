package io.micronaut.security.token;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProfileClaimsTest {

    @Test
    void profileClaimConstantsMatchOpenIdConnectStandardClaimNames() {
        assertEquals("sub", ProfileClaims.CLAIM_SUB);
        assertEquals("name", ProfileClaims.CLAIM_NAME);
        assertEquals("given_name", ProfileClaims.CLAIM_GIVEN_NAME);
        assertEquals("family_name", ProfileClaims.CLAIM_FAMILY_NAME);
        assertEquals("middle_name", ProfileClaims.CLAIM_MIDDLE_NAME);
        assertEquals("nickname", ProfileClaims.CLAIM_NICKNAME);
        assertEquals("preferred_username", ProfileClaims.CLAIM_PREFERRED_USERNAME);
        assertEquals("profile", ProfileClaims.CLAIM_PROFILE);
        assertEquals("picture", ProfileClaims.CLAIM_PICTURE);
        assertEquals("website", ProfileClaims.CLAIM_WEBSITE);
        assertEquals("email", ProfileClaims.CLAIM_EMAIL);
        assertEquals("email_verified", ProfileClaims.CLAIM_EMAIL_VERIFIED);
        assertEquals("gender", ProfileClaims.CLAIM_GENDER);
        assertEquals("birthdate", ProfileClaims.CLAIM_BIRTHDATE);
        assertEquals("zoneinfo", ProfileClaims.CLAIM_ZONEINFO);
        assertEquals("locale", ProfileClaims.CLAIM_LOCALE);
        assertEquals("phone_number", ProfileClaims.CLAIM_PHONE_NUMBER);
        assertEquals("phone_number_verified", ProfileClaims.CLAIM_PHONE_NUMBER_VERIFIED);
        assertEquals("address", ProfileClaims.CLAIM_ADDRESS);
        assertEquals("updated_at", ProfileClaims.CLAIM_UPDATED_AT);
    }

    @Test
    void allReturnsEveryProfileClaimConstant() {
        assertEquals(Set.of(
                ProfileClaims.CLAIM_SUB,
                ProfileClaims.CLAIM_NAME,
                ProfileClaims.CLAIM_GIVEN_NAME,
                ProfileClaims.CLAIM_FAMILY_NAME,
                ProfileClaims.CLAIM_MIDDLE_NAME,
                ProfileClaims.CLAIM_NICKNAME,
                ProfileClaims.CLAIM_PREFERRED_USERNAME,
                ProfileClaims.CLAIM_PROFILE,
                ProfileClaims.CLAIM_PICTURE,
                ProfileClaims.CLAIM_WEBSITE,
                ProfileClaims.CLAIM_EMAIL,
                ProfileClaims.CLAIM_EMAIL_VERIFIED,
                ProfileClaims.CLAIM_GENDER,
                ProfileClaims.CLAIM_BIRTHDATE,
                ProfileClaims.CLAIM_ZONEINFO,
                ProfileClaims.CLAIM_LOCALE,
                ProfileClaims.CLAIM_PHONE_NUMBER,
                ProfileClaims.CLAIM_PHONE_NUMBER_VERIFIED,
                ProfileClaims.CLAIM_ADDRESS,
                ProfileClaims.CLAIM_UPDATED_AT
        ), ProfileClaims.all());
    }

    @Test
    void allReturnsOnlyDeclaredClaimConstants() throws IllegalAccessException {
        Map<String, String> claimConstants = declaredClaimConstants();

        assertEquals(claimConstants.size(), ProfileClaims.all().size());
        assertTrue(ProfileClaims.all().containsAll(claimConstants.values()));
    }

    @Test
    void constructorIsPrivate() {
        Constructor<?>[] constructors = ProfileClaims.class.getDeclaredConstructors();

        assertEquals(1, constructors.length);
        assertTrue(Modifier.isPrivate(constructors[0].getModifiers()));
    }

    private static Map<String, String> declaredClaimConstants() throws IllegalAccessException {
        Map<String, String> result = new LinkedHashMap<>();
        for (var field : ProfileClaims.class.getDeclaredFields()) {
            int modifiers = field.getModifiers();
            if (field.getName().startsWith("CLAIM_")
                    && field.getType().equals(String.class)
                    && Modifier.isPublic(modifiers)
                    && Modifier.isStatic(modifiers)
                    && Modifier.isFinal(modifiers)) {
                result.put(field.getName(), (String) field.get(null));
            }
        }
        return result;
    }
}
