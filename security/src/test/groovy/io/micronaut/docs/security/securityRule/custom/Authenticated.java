package io.micronaut.docs.security.securityRule.custom;

import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Secured(SecurityRule.IS_AUTHENTICATED)
@interface Authenticated {
}
