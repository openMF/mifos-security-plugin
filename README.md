# Mifos® Security Plugin for Apache Fineract®

## For Users

1. Download the Mifos® Security Plugin and extract the files (all the libraries required for running it are included). **It is very important to use the specific versions according to the Apache Fineract**

| Apache Fineract | Mifos Reporting Plugin | Download Link |
| :---         |     :---:      |          ---: |
| 1.12.0   | 1.12.1     | [Mifos® Security Plugin v1.12.1](https://sourceforge.net/projects/mifos/files/mifos-plugins/MifosSecurityPlugin/MifosSecurityPlugin-1.12.1.zip/download)     |
| 1.11.0     | 1.11.0       | [Mifos® Security Plugin v1.11.0](https://sourceforge.net/projects/mifos/files/mifos-plugins/MifosReportingPlugin/FineractPentahoPlugin-1.11.zip/download)      |

2. Option 1 - Execute only for Docker® - Create a directory, copy the Mifos® Security Plugin libraries in it

```bash
    mkdir mifos-security-plugin  && cd mifos-security-plugin
```

2.  Option 2 - Execute only for Apache Tomcat® - Copy the Mifos® Security Plugin libraries in $TOMCAT_HOME/webapps/fineract-provider/WEB-INF/lib/

3. Restart Docker® or Apache Tomcat®

4. Test the Mifos® Secuirty.

## For Developers

This project is currently only tested against the very latest and greatest bleeding edge Apache Fineract® `develop` branch on Linux Ubuntu® 24.04LTS. 
Building and using it against other Apache Fineract® versions may be possible, but is not tested or documented here.

1. Download and compile

```bash
    git clone https://github.com/openMF/mifos-security-plugin.git
    cd mifos-security-plugin && ./mvnw -Dmaven.test.skip=true clean package && cd ..
```

3. Execute Apache Fineract® with the location of the Mifos® Security Plugin library

```bash
java -Dloader.path=$MIFOS_SECURITY_PLUGIN_HOME/libs/ -jar $APACHE_FINERACT_HOME/fineract-provider.jar
```


Please note that the library will work using the latest Apache Fineract® development branch (10th August 2025), also make sure you got installed the type fonts required by the reports. This Mifos® Security Plugin will work only on Apache Tomcat® version 10+. 


## License

This code used to be part of the Mifos® codebase before it became [Apache Fineract®](https://fineract.apache.org).

Note that the code and report templates in this git repo itself are
[licensed to you under the Mozilla® Public License 2.0 (MPL)](https://github.com/openMF/mifos-security-plugin/blob/develop/LICENSE).

## Important

* Mifos® and Mifos® Security Plugin are not affiliated with, endorsed by, or otherwise associated with the Apache Software Foundation® (ASF) or any of its projects.
* Apache Software Foundation® is a vendor-neutral organization and it is an important part of the brand is that Apache Software Foundation® (ASF) projects are governed independently.
* Apache Fineract®, Fineract, Apache, the Apache® feather, and the Apache Fineract® project logo are either registered trademarks or trademarks of the Apache Software Foundation®.

## Contribute

If this Mifos® Security Plugin project is useful to you, please contribute back to it (and to Apache Fineract®) by raising Pull Requests yourself with any enhancements you make, and by helping to maintain this project by helping other users on Issues and reviewing PR from others (you will be promoted to committer on this project when you contribute).  
We recommend that you _Watch_ and _Star_ this project on GitHub® to make it easy to get notified.

## History

This is a [Mifos® Security Plugin for Apache Fineract®](https://github.com/apache/fineract/blob/maintenance/1.6/fineract-doc/src/docs/en/deployment.adoc). 




