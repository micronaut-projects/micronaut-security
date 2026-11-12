plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(projects.micronautSecurityPassword)
    implementation(libs.bcprov)
    testImplementation(projects.micronautSecurityPasswordTck)
}
micronautBuild {
    testFramework = io.micronaut.build.TestFramework.JUNIT6
    binaryCompatibility.enabledAfter("5.5.0")
}
