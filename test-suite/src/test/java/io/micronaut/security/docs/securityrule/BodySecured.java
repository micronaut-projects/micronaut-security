package io.micronaut.security.docs.securityrule;

//tag::clazz[]
import io.micronaut.aop.Around;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Around
@Documented
public @interface BodySecured {
}
//end::clazz[]