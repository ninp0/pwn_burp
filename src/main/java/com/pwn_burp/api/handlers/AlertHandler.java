package com.pwn_burp.api.handlers;

import com.google.gson.Gson;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.openapi.*;

public class AlertHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public AlertHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.post("/alert", this::issueAlert);
    }

    @OpenApi(
            summary = "Issue an alert",
            operationId = "issueAlert",
            path = "/alert",
            methods = {HttpMethod.POST},
            requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = Message.class)}),
            responses = {
                    @OpenApiResponse(status = "201", description = "Alert issued")
            }
    )
    private void issueAlert(Context ctx) {
        Message message = gson.fromJson(ctx.body(), Message.class);
        pwnService.issueAlert(message.message);
        ctx.status(201);
        ctx.result("");
    }
}
