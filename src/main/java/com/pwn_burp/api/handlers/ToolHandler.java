package com.pwn_burp.api.handlers;

import com.google.gson.Gson;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.openapi.*;

import java.util.Base64;

public class ToolHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public ToolHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.post("/send/{tool}", this::sendToTool);
    }

    @OpenApi(
            summary = "Send request to Intruder or Repeater",
            operationId = "sendToTool",
            path = "/send/{tool}",
            methods = {HttpMethod.POST},
            pathParams = {@OpenApiParam(name = "tool", description = "Tool name (intruder or repeater)", required = true)},
            requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = ScanMessage.class)}),
            responses = {
                    @OpenApiResponse(status = "200", description = "Request sent to tool"),
                    @OpenApiResponse(status = "404", description = "Tool not found", content = {@OpenApiContent(from = ApiResponse.class)})
            }
    )
    private void sendToTool(Context ctx) {
        String tool = ctx.pathParam("tool");
        ScanMessage scanMSG = gson.fromJson(ctx.body(), ScanMessage.class);
        switch (tool) {
            case "intruder":
                pwnService.sendToIntruder(
                        scanMSG.host, scanMSG.port, scanMSG.useHttps,
                        Base64.getDecoder().decode(scanMSG.request));
                ctx.status(200);
                ctx.result("");
                break;
            case "repeater":
                pwnService.sendToRepeater(
                        scanMSG.host, scanMSG.port, scanMSG.useHttps,
                        Base64.getDecoder().decode(scanMSG.request), "pwn");
                ctx.status(200);
                ctx.result("");
                break;
            default:
                ctx.status(404);
                ctx.json(pwnService.apiError("tool", "tool not found"));
        }
    }
}
