#  Mifos® Security Plugin for Apache Fineract®

This plugin extends Apache Fineract® functionality by adding additional security controls, external authentication, custom validations, and more.

---

##  For Users

### 1. Clone or download Apache Fineract®

```bash
git clone https://github.com/apache/fineract.git
cd fineract
```

### 2. Generate the Fineract `.jar`

```bash
./gradlew bootJar
```

This will generate the `fineract-provider-<version>.jar` file in `fineract-provider/build/libs/`.

---

##  Installing the Security Plugin

### 1. Clone the plugin repository

```bash
git clone https://github.com/your-org/fineract-security-plugin.git
cd fineract-security-plugin
```

### 2. Manually install Fineract `.jar` files into the local Maven repository

> Only if the plugin directly depends on Fineract classes and you're not using a remote repository.

```bash
mvn install:install-file \
  -Dfile=/path/to/fineract/fineract-provider/build/libs/fineract-provider-1.13.1-SNAPSHOT.jar \
  -DgroupId=org.apache.fineract \
  -DartifactId=fineract-provider \
  -Dversion=1.13.1-SNAPSHOT \
  -Dpackaging=jar

mvn install:install-file \
  -Dfile=/path/to/fineract/fineract-core/build/libs/fineract-core-1.13.1-SNAPSHOT.jar \
  -DgroupId=org.apache.fineract \
  -DartifactId=fineract-core \
  -Dversion=1.13.1-SNAPSHOT \
  -Dpackaging=jar
```

>  Make sure to adjust the paths and versions according to your environment.

### 3. Build the security plugin using Maven

```bash
mvn clean install
```

This will generate the plugin `.jar` inside the `target/` directory, along with its dependencies in the `libs/` folder (if configured that way).

---

##  Running the Plugin with Apache Fineract®

1. Make sure the plugin `.jar` and its dependencies are placed in a directory (e.g., `/home/user/plugins/libs/`).

2. Run Apache Fineract® while dynamically loading the plugin:

```bash
java -Dloader.path=/home/user/plugins/libs/ \
     -jar /path/to/fineract/fineract-provider/build/libs/fineract-provider-1.13.1-SNAPSHOT.jar \
     --debug
```

>  If everything is correctly set up, the logs should indicate that the plugin was successfully loaded and registered.

---

##  Verification

You can test the plugin's features by calling a custom endpoint or reviewing changes in the existing security logic. For example:

```bash
curl -k --location --request GET 'https://localhost:8443/fineract-provider/auth/test' \
--header 'Fineract-Platform-TenantId: default'
```

---

##  Requirements

* Apache Fineract® 1.13.1+
* Java 11 or later
* Maven 3.6+
* Gradle 7+ (to build Fineract)
* Ubuntu 20.04/22.04/24.04 (recommended)

---

##  License

This project is licensed under the [Mozilla Public License 2.0 (MPL)](https://www.mozilla.org/en-US/MPL/2.0/).

---

##  Contributions

Contributions are welcome! You can:

* Submit a pull request with improvements or fixes
* Report bugs and suggestions via the Issues section
* Share the plugin with other developers in the Fineract® ecosystem

