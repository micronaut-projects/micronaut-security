import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-full-coverage")
}
dependencies {
    api(projects.micronautSecurityPassword)
    api(mnTest.micronaut.test.junit5)
    api(mnTest.junit.jupiter.params)

    testAnnotationProcessor(mn.micronaut.inject.java)
    testAnnotationProcessor(mnValidation.micronaut.validation.processor)
    testImplementation(mnTest.junit.platform.suite)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.5.0")
    testFramework = TestFramework.JUNIT6
}
