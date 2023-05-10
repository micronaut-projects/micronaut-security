plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    implementation(mn.micronaut.core.processor)
//    compileOnly(projects.micronautSecurity)
}
