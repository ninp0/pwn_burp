package com.pwn_burp.api;

import com.pwn_burp.burp.*;
import com.pwn_burp.config.ConfigManager;
import com.pwn_burp.api.handlers.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.openapi.plugin.OpenApiPlugin;
import io.javalin.openapi.plugin.swagger.SwaggerPlugin;
import io.javalin.http.staticfiles.Location;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

public class RestServer {
    private final ConfigManager config;
    private final PwnService pwnService;
    private Javalin server;
    private final Logger logger = LoggerFactory.getLogger(RestServer.class);

    public RestServer(ConfigManager config, PwnService pwnService) {
        this.config = config;
        this.pwnService = pwnService;
    }

    public void start() {
        try {
            this.server = Javalin.create(javalinConfig -> {
                javalinConfig.registerPlugin(new OpenApiPlugin(openApiConfig -> {
                    openApiConfig.withDocumentationPath("/openapi.json");
                }));

                javalinConfig.staticFiles.add(staticFileConfig -> {
                    staticFileConfig.directory = "/swagger-ui";
                    staticFileConfig.location = Location.CLASSPATH;
                });

                // === EXTENDED HTTP REQUEST TIMEOUTS ===
                // Jetty's default idle timeout is only 30 seconds.
                // This is the most common cause of "Idle timeout expired" errors
                // on long-running endpoints (scans, proxy operations, etc.).
                // We extend both the async timeout and the connector idle timeout
                // to 10 minutes. Adjust the value if you need even longer requests.
                long timeoutMs = 10 * 60 * 1000L; // 10 minutes

                // Async timeout (used by ctx.future(), ctx.async(), etc.)
                javalinConfig.http.asyncTimeout = timeoutMs;

                // Jetty connection idle timeout (applies to all requests)
                javalinConfig.jetty.modifyServer(jettyServer -> {
                    for (Connector connector : jettyServer.getConnectors()) {
                        if (connector instanceof ServerConnector) {
                            ((ServerConnector) connector).setIdleTimeout(timeoutMs);
                        }
                    }
                });
            });

            this.server.exception(Exception.class, (e, ctx) -> {
                ctx.status(400).json(pwnService.apiError("error", e.getMessage()));
            });

            new PingHandler(pwnService).register(this.server);
            new ScopeHandler(pwnService).register(this.server);
            new ScanHandler(pwnService).register(this.server);
            new ShutdownHandler(pwnService).register(this.server);
            new SiteMapHandler(pwnService).register(this.server);
            new ProxyHandler(pwnService).register(this.server);
            new CookieJarHandler(pwnService).register(this.server);
            new AlertHandler(pwnService).register(this.server);
            new RepeaterHandler(pwnService).register(this.server);

            this.server.start(this.config.getServerAddress(), this.config.getServerPort());
            this.pwnService.getLogging().logToOutput(
                "REST API started.  Swagger UI available at http://" + this.config.getServerAddress() + ":" + this.config.getServerPort()
            );
        } catch (Exception e) {
            logger.error("Failed to start REST server on " + config.getServerAddress() + ":" + config.getServerPort() + ": " + e.getMessage());
            throw new RuntimeException("Failed to start REST server", e);
        }
    }

    public void stop() {
        if (this.server != null) {
            this.server.stop();
            this.pwnService.getLogging().logToOutput("REST API server stopped");
        }
    }
}
