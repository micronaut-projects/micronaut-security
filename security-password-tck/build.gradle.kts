import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(projects.micronautSecurityPassword)
    api(mnTest.micronaut.test.junit5)
    api(mnTest.junit.jupiter.params)

    testAnnotationProcessor(mnValidation.micronaut.validation.processor)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.5.0")
    testFramework = TestFramework.JUNIT6
}
