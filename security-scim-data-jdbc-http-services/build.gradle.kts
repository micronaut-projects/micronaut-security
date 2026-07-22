import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mn.micronaut.inject.java)

    api(projects.micronautSecurityScimDataJdbc)
    api(projects.micronautSecurityScimHttpServices)

    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(projects.micronautSecurityScimHttpServer)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mnSql.h2)
    testImplementation(mnSql.micronaut.jdbc.hikari)
    testRuntimeOnly(mnLogging.logback.classic)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.4.0")
    testFramework = TestFramework.JUNIT6
}
