import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mnValidation.micronaut.validation.processor)

    api(projects.micronautSecurityScimHttpServices)
    api(mn.micronaut.http.server)

    compileOnly(mnValidation.micronaut.validation)

    testRuntimeOnly(mnSql.h2)
    testImplementation(mnSql.micronaut.jdbc.hikari)
    testImplementation(projects.micronautSecurityScimDataJdbcHttpServices)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mnValidation.micronaut.validation)
    testRuntimeOnly(mnLogging.logback.classic)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.4.0")
    testFramework = TestFramework.JUNIT6
}
