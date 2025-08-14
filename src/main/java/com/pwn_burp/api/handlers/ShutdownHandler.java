package com.pwn_burp.api.handlers;

import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;

public class ShutdownHandler {
    private final PwnService pwnService;

    public ShutdownHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.post("/shutdown", this::shutdown);
    }

    @OpenApi(
            summary = "Shutdown Burp Suite Pro gracefully",
            operationId = "shutdown",
            path = "/shutdown",
            methods = {HttpMethod.POST},
            responses = {
                    @OpenApiResponse(status = "200", description = "Shutdown initiated", content = {@OpenApiContent(type = "text/plain")})
            }
    )
    private void shutdown(Context ctx) {
        // Initiate graceful shutdown using Montoya API
        pwnService.shutdown();
        ctx.status(200);
        ctx.result("Shutdown initiated");
    }
}
