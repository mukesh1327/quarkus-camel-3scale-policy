package com.cloudxplorer13;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.support.jsse.*;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.nio.file.Files;
import java.nio.file.Path;

@ApplicationScoped
public class ProxyRoute extends RouteBuilder {

    private static final Logger log = Logger.getLogger(ProxyRoute.class);

    // -----------------------------
    // Incoming TLS (Server)
    // -----------------------------
    @Inject
    @ConfigProperty(name = "app.https.enabled", defaultValue = "false")
    boolean tlsEnabled;

    @Inject
    @ConfigProperty(name = "app.https.keystore.file", defaultValue = "")
    String keystoreFile;

    @Inject
    @ConfigProperty(name = "app.https.keystore.password", defaultValue = "changeit")
    String keystorePassword;

    @Inject
    @ConfigProperty(name = "app.https.keystore.key-password", defaultValue = "changeit")
    String keyPassword;

    // -----------------------------
    // Outgoing TLS (Client)
    // -----------------------------
    @Inject
    @ConfigProperty(name = "app.https.truststore.file", defaultValue = "")
    String trustStoreFile;

    @Inject
    @ConfigProperty(name = "app.https.truststore.password", defaultValue = "changeit")
    String trustStorePassword;

    @Inject
    org.apache.camel.CamelContext camelContext;

    @Override
    public void configure() throws Exception {

        // -----------------------------
        // 1. Server SSL (Incoming)
        // -----------------------------
        String routeUri = "netty-http:proxy://0.0.0.0:8080";

        if (tlsEnabled && keystoreFile != null && !keystoreFile.isBlank()) {
            Path ksPath = Path.of(keystoreFile.startsWith("file:") ? keystoreFile.substring(5) : keystoreFile);

            if (Files.exists(ksPath)) {
                KeyStoreParameters ksp = new KeyStoreParameters();
                ksp.setResource("file:" + ksPath.toAbsolutePath());
                ksp.setPassword(keystorePassword);
                ksp.setType("PKCS12");

                KeyManagersParameters kmp = new KeyManagersParameters();
                kmp.setKeyStore(ksp);
                kmp.setKeyPassword(keyPassword);

                SSLContextParameters serverSsl = new SSLContextParameters();
                serverSsl.setKeyManagers(kmp);

                camelContext.getRegistry().bind("sslContextParameters", serverSsl);
                routeUri = "netty-http:proxy://0.0.0.0:8443?ssl=true&sslContextParameters=#sslContextParameters";

                log.infof("TLS enabled. Listening on %s", routeUri);
            } else {
                log.warnf("TLS enabled but keystore %s not found. Falling back to HTTP.", keystoreFile);
            }
        }

        // -----------------------------
        // 2. Client SSL (Outgoing)
        // -----------------------------
        if (trustStoreFile != null && !trustStoreFile.isBlank() && Files.exists(Path.of(trustStoreFile))) {
            KeyStoreParameters tsp = new KeyStoreParameters();
            tsp.setResource("file:" + trustStoreFile);
            tsp.setPassword(trustStorePassword);

            TrustManagersParameters tmp = new TrustManagersParameters();
            tmp.setKeyStore(tsp);

            SSLContextParameters clientSsl = new SSLContextParameters();
            clientSsl.setTrustManagers(tmp);

            camelContext.getRegistry().bind("clientSsl", clientSsl);
            log.info("Client SSL configured for outgoing HTTPS requests.");
        }

        // -----------------------------
        // 3. Main Proxy Route
        // -----------------------------
        from(routeUri)
            .routeId("dynamic-proxy-route")

            // Log incoming request
            .process(this::logIncomingRequest)

            // Forward dynamically to target backend
            .toD("netty-http:${headers.CamelHttpScheme}://${headers.CamelHttpHost}:${headers.CamelHttpPort}${headers.CamelHttpPath}"
                + "?bridgeEndpoint=true&throwExceptionOnFailure=true&sslContextParameters=#clientSsl")

            // Log outgoing response
            .process(this::logOutgoingResponse)

            // Error handling
            .onException(Exception.class)
                .handled(true)
                .process(this::handleProxyError);
    }

    // -----------------------------
    // Helper Methods
    // -----------------------------
    private void logIncomingRequest(Exchange exchange) {
        log.infof("Incoming request: method=%s, path=%s, headers=%s",
                exchange.getIn().getHeader("CamelHttpMethod"),
                exchange.getIn().getHeader("CamelHttpPath"),
                maskHeaders(exchange));
    }

    private void logOutgoingResponse(Exchange exchange) {
        log.infof("Outgoing response: status=%s, body=%s",
                exchange.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE),
                exchange.getMessage().getBody(String.class));
    }

    private void handleProxyError(Exchange exchange) {
        Exception exception = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
        log.error("Proxy error: ", exception);
        exchange.getMessage().setBody("Proxy error: " + exception.getMessage());
        exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_CODE, 502);
    }

    private String maskHeaders(Exchange exchange) {
        return exchange.getIn().getHeaders().entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                        e -> e.getKey(),
                        e -> e.getKey().equalsIgnoreCase("Authorization") ? "****" : String.valueOf(e.getValue())
                )).toString();
    }
}
