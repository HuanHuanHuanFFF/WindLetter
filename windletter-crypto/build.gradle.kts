val bouncyCastleVersion: String by rootProject.extra
val junitVersion: String by rootProject.extra

dependencies {
    api(project(":windletter-core"))

    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcpkix-jdk18on:$bouncyCastleVersion")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
