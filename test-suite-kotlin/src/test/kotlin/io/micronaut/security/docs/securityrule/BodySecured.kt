package io.micronaut.security.docs.securityrule

import io.micronaut.aop.Around

//tag::clazz[]
@Target(AnnotationTarget.FUNCTION)
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
@Around
@MustBeDocumented
annotation class BodySecured
//end::clazz[]