import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mnData.micronaut.data.processor)
    annotationProcessor(mnValidation.micronaut.validation.processor)
    api(mnValidation.validation)
    implementation(mnData.micronaut.data.model)
    compileOnly(mnValidation.micronaut.validation)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnValidation.micronaut.validation)
    testRuntimeOnly(mnLogging.logback.classic)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.4.0")
    testFramework = TestFramework.JUNIT6
}
