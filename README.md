# camel-3scale-logger

This project uses Quarkus, the Supersonic Subatomic Java Framework.

If you want to learn more about Quarkus, please visit its website: <https://quarkus.io/>.

## Running the application in dev mode

You can run your application in dev mode that enables live coding using:

```shell script
./mvnw quarkus:dev
```

> **_NOTE:_**  Quarkus now ships with a Dev UI, which is available in dev mode only at <http://localhost:8080/q/dev/>.

## Packaging and running the application

The application can be packaged using:

```shell script
./mvnw package
```

It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

The application is now runnable using `java -jar target/quarkus-app/quarkus-run.jar`.

If you want to build an _über-jar_, execute the following command:

```shell script
./mvnw package -Dquarkus.package.jar.type=uber-jar
```

The application, packaged as an _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

## Creating a native executable

You can create a native executable using:

```shell script
./mvnw package -Dnative
```

Or, if you don't have GraalVM installed, you can run the native executable build in a container using:

```shell script
./mvnw package -Dnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/camel-3scale-logger-1.0.0-SNAPSHOT-runner`

If you want to learn more about building native executables, please consult <https://quarkus.io/guides/maven-tooling>.

## Related Guides

- Camel Core ([guide](https://docs.redhat.com/en/documentation/red_hat_build_of_apache_camel/4.10/html-single/red_hat_build_of_apache_camel_for_quarkus_reference/camel-quarkus-extensions-reference#extensions-core)): Camel core functionality and basic Camel languages: Constant, ExchangeProperty, Header, Ref, Simple and Tokenize
- Logging JSON ([guide](https://quarkus.io/guides/logging#json-logging)): Add JSON formatter for console logging
- Camel Netty HTTP ([guide](https://docs.redhat.com/en/documentation/red_hat_build_of_apache_camel/4.10/html-single/red_hat_build_of_apache_camel_for_quarkus_reference/camel-quarkus-extensions-reference#extensions-netty-http)): Netty HTTP server and client using the Netty 4.x


Test https for svc from 

oc run -i --rm temp-network-tools   --image=registry.redhat.io/openshift4/network-tools-rhel8@sha256:7dda9326091cc06ab002bf6bdbddea0830235f5c4e85df72d3a828736898587a   --restart=Never   --tty -- /bin/bash