import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(mn.micronaut.http)
    implementation(mnValidation.validation) // jakarta.validation:jakarta.validation-api, only used internally
    annotationProcessor(mnValidation.micronaut.validation.processor)
    testImplementation(mnValidation.micronaut.validation)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.5.0")
    testFramework = TestFramework.JUNIT6
}
