plugins {
    id("io.micronaut.build.internal.security-full-coverage")
}
dependencies {
    api(projects.micronautSecurityPassword)
    implementation(libs.managed.bcprov.jdk18on)
    testImplementation(projects.micronautSecurityPasswordTck)
}
micronautBuild {
    testFramework = io.micronaut.build.TestFramework.JUNIT6
    binaryCompatibility.enabledAfter("5.5.0")
}
