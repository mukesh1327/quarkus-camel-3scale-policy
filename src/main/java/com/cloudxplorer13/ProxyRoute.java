package com.cloudxplorer13;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.support.jsse.*;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

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
    CamelContext camelContext;

    @Override
    public void configure() throws Exception {
        configureErrorHandling();

        String routeUri = configureServerTls();
        configureClientTls();

        from(routeUri)
            .routeId("dynamic-proxy-route")
            .process(this::logIncomingRequest)
            .toD(buildDynamicUri()) // Dynamic target URI with SSL if available
            .process(this::logOutgoingResponse);
    }

    // -----------------------------
    // SSL Configuration
    // -----------------------------
    private String configureServerTls() throws Exception {
        String routeUri = "netty-http:proxy://0.0.0.0:8080";

        if (tlsEnabled && !keystoreFile.isBlank()) {
            Path ksPath = Path.of(keystoreFile.replaceFirst("^file:", ""));
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

                log.infof("[INFO] TLS enabled. Listening on %s", routeUri);
            } else {
                log.warnf("[WARN] TLS enabled but keystore not found at %s. Falling back to HTTP.", keystoreFile);
            }
        } else {
            log.info("[INFO] TLS disabled. Listening on HTTP 8080");
        }

        return routeUri;
    }

    private void configureClientTls() throws Exception {
        if (!trustStoreFile.isBlank() && Files.exists(Path.of(trustStoreFile))) {
            KeyStoreParameters tsp = new KeyStoreParameters();
            tsp.setResource("file:" + trustStoreFile);
            tsp.setPassword(trustStorePassword);

            TrustManagersParameters tmp = new TrustManagersParameters();
            tmp.setKeyStore(tsp);

            SSLContextParameters clientSsl = new SSLContextParameters();
            clientSsl.setTrustManagers(tmp);

            camelContext.getRegistry().bind("clientSsl", clientSsl);
            log.info("[INFO] Client SSL configured for outgoing HTTPS requests.");
        } else {
            log.info("[INFO] No client truststore found. Outgoing HTTPS will use default JVM truststore.");
        }
    }

    // -----------------------------
    // Route Helpers
    // -----------------------------
    private String buildDynamicUri() {
        return "netty-http:${headers.CamelHttpScheme}://${headers.CamelHttpHost}:${headers.CamelHttpPort}${headers.CamelHttpPath}"
                + "?bridgeEndpoint=true&throwExceptionOnFailure=true"
                + "&sslContextParameters=#clientSsl";
    }

    private void configureErrorHandling() {
        onException(Exception.class)
            .handled(true)
            .process(this::handleProxyError);
    }

    // -----------------------------
    // Logging Helpers
    // -----------------------------
    private void logIncomingRequest(Exchange exchange) {
        String traceContext = getTraceContext(exchange);
        log.infof("%s Incoming request: method=%s, path=%s, headers=%s",
                traceContext,
                exchange.getIn().getHeader("CamelHttpMethod"),
                exchange.getIn().getHeader("CamelHttpPath"),
                maskHeaders(exchange));
    }

    private void logOutgoingResponse(Exchange exchange) {
        String traceContext = getTraceContext(exchange);
        log.infof("%s Outgoing response: status=%s, body=%s",
                traceContext,
                exchange.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE),
                exchange.getMessage().getBody(String.class));
    }

    private void handleProxyError(Exchange exchange) {
        Exception exception = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
        String traceContext = getTraceContext(exchange);
        log.errorf("%s Proxy error: %s", traceContext, exception.getMessage(), exception);
        exchange.getMessage().setBody("Proxy error: " + exception.getMessage());
        exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_CODE, 502);
    }

    private String maskHeaders(Exchange exchange) {
        return exchange.getIn().getHeaders().entrySet().stream()
                .collect(Collectors.toMap(
                        e -> e.getKey(),
                        e -> e.getKey().equalsIgnoreCase("Authorization") ? "****" : String.valueOf(e.getValue())
                )).toString();
    }

    private String getTraceContext(Exchange exchange) {
        // Use official Quarkus OTEL property
        String traceId = exchange.getIn().getHeader("traceparent", String.class);
        return traceId != null ? "[traceparent=" + traceId + "]" : "";
    }
}
