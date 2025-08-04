package com.pwn_burp.api.handlers;

import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;

public class PingHandler {
    private final PwnService pwnService;

    public PingHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/ping", this::ping);
    }

    @OpenApi(
            summary = "Ping the API",
            operationId = "ping",
            path = "/ping",
            methods = {HttpMethod.GET},
            responses = {
                    @OpenApiResponse(status = "200", description = "PONG response", content = {@OpenApiContent(type = "text/plain")})
            }
    )
    private void ping(Context ctx) {
        ctx.status(200);
        ctx.result("PONG");
    }
}
