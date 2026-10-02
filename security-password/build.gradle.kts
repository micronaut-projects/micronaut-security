import io.micronaut.build.TestFramework
plugins {
    id("io.micronaut.build.internal.security-full-coverage")
}
dependencies {
    annotationProcessor(mnValidation.micronaut.validation.processor)
    api(mnValidation.validation)
    implementation(mnValidation.micronaut.validation)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.5.0")
    testFramework = TestFramework.JUNIT6
}
