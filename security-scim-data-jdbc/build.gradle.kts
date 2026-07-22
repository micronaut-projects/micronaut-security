import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mnData.micronaut.data.processor)
    annotationProcessor(mnValidation.micronaut.validation.processor)
    api(mnValidation.validation)
    api(projects.micronautSecurityScimData)
    api(mnData.micronaut.data.jdbc)
    compileOnly(mnValidation.micronaut.validation)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnValidation.micronaut.validation)
    testImplementation(mnSql.h2)
    testImplementation(mnSql.micronaut.jdbc.hikari)
    testRuntimeOnly(mnLogging.logback.classic)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.4.0")
    testFramework = TestFramework.JUNIT6
}
