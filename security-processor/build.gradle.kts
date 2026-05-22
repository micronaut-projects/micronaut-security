plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    compileOnly(mn.micronaut.core.processor)
    implementation(projects.micronautSecurityAnnotations)
}

micronautBuild {
    binaryCompatibility {
        enabled.set(false)
    }
}
