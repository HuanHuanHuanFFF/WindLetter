plugins {
    java
    `maven-publish`
}

val bouncyCastleVersion by extra("1.78.1")
val jcsVersion by extra("1.1")
val zstdVersion by extra("1.5.6-10")
val junitVersion by extra("5.10.2")

group = "com.windletter"
version = "0.1.0-SNAPSHOT"

allprojects {
    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "maven-publish")

    group = rootProject.group
    version = rootProject.version

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}
