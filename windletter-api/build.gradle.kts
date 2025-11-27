val junitVersion: String by rootProject.extra
val bouncyCastleVersion: String by rootProject.extra

dependencies {
    api(project(":windletter-core"))
    api(project(":windletter-crypto"))
    api(project(":windletter-protocol"))
    implementation(project(":windletter-armor"))
    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
