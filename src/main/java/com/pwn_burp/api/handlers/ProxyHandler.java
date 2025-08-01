package com.pwn_burp.api.handlers;

import com.google.gson.Gson;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.openapi.*;

public class ProxyHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public ProxyHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/proxyhistory", this::getProxyHistory);
        server.post("/proxy/intercept/enable", this::enableProxyIntercept);
        server.post("/proxy/intercept/disable", this::disableProxyIntercept);
        server.get("/proxy/listeners", this::getProxyListeners);
        server.post("/proxy/listeners", this::addProxyListener);
        server.put("/proxy/listeners/{id}", this::updateProxyListener);
        server.delete("/proxy/listeners/{id}", this::deleteProxyListener);
    }

    @OpenApi(
            summary = "Get proxy history",
            operationId = "getProxyHistory",
            path = "/proxyhistory",
            methods = {HttpMethod.GET},
            responses = {
                    @OpenApiResponse(status = "200", description = "List of proxy history entries", content = {@OpenApiContent(type = "application/json")})
            }
    )
    private void getProxyHistory(Context ctx) {
        ctx.status(200);
        ctx.json(pwnService.getProxyHistory());
    }

    @OpenApi(
            summary = "Enable proxy interception",
            operationId = "enableProxyIntercept",
            path = "/proxy/intercept/enable",
            methods = {HttpMethod.POST},
            responses = {
                    @OpenApiResponse(status = "200", description = "Proxy interception enabled")
            }
    )
    private void enableProxyIntercept(Context ctx) {
        pwnService.setProxyInterceptionEnabled(true);
        ctx.status(200);
        //ctx.result("{\"proxy\": \"enabled\"}");
        ctx.json(new ApiResponse("proxy", "enabled"));
    }

    @OpenApi(
            summary = "Disable proxy interception",
            operationId = "disableProxyIntercept",
            path = "/proxy/intercept/disable",
            methods = {HttpMethod.POST},
            responses = {
                    @OpenApiResponse(status = "200", description = "Proxy interception disabled")
            }
    )
    private void disableProxyIntercept(Context ctx) {
        pwnService.setProxyInterceptionEnabled(false);
        ctx.status(200);
        //ctx.result("{\"proxy\": \"disabled\"}");
        ctx.json(new ApiResponse("proxy", "disabled"));
    }

    @OpenApi(
            summary = "Get all proxy listeners",
            operationId = "getProxyListeners",
            path = "/proxy/listeners",
            methods = {HttpMethod.GET},
            responses = {
                    @OpenApiResponse(status = "200", description = "List of proxy listeners", content = {@OpenApiContent(from = ProxyListener[].class)})
            }
    )
    private void getProxyListeners(Context ctx) {
        ctx.status(200);
        ctx.json(pwnService.getProxyListeners());
    }

    @OpenApi(
            summary = "Add a new proxy listener",
            operationId = "addProxyListener",
            path = "/proxy/listeners",
            methods = {HttpMethod.POST},
            requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = ProxyListener.class)}),
            responses = {
                    @OpenApiResponse(status = "201", description = "Proxy listener added", content = {@OpenApiContent(from = ProxyListener.class)}),
                    @OpenApiResponse(status = "400", description = "Invalid listener settings", content = {@OpenApiContent(from = ApiResponse.class)})
            }
    )
    private void addProxyListener(Context ctx) {
        ProxyListener listener = gson.fromJson(ctx.body(), ProxyListener.class);
        if (listener == null || listener.getBindAddress() == null || listener.getPort() <= 0) {
            ctx.status(400);
            ctx.json(pwnService.apiError("listener", "Invalid bind address or port"));
            return;
        }
        boolean success = pwnService.addProxyListener(listener.getBindAddress(), listener.getPort());
        if (success) {
            ctx.status(201);
            ctx.json(listener);
        } else {
            ctx.status(400);
            ctx.json(pwnService.apiError("listener", "Failed to add proxy listener (unsupported in Montoya API)"));
        }
    }

    @OpenApi(
            summary = "Update a proxy listener",
            operationId = "updateProxyListener",
            path = "/proxy/listeners/{id}",
            methods = {HttpMethod.PUT},
            pathParams = {@OpenApiParam(name = "id", description = "ID of the proxy listener", required = true)},
            requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = ProxyListener.class)}),
            responses = {
                    @OpenApiResponse(status = "200", description = "Proxy listener updated", content = {@OpenApiContent(from = ProxyListener.class)}),
                    @OpenApiResponse(status = "400", description = "Invalid listener settings", content = {@OpenApiContent(from = ApiResponse.class)}),
                    @OpenApiResponse(status = "404", description = "Proxy listener not found", content = {@OpenApiContent(from = ApiResponse.class)})
            }
    )
    private void updateProxyListener(Context ctx) {
        String id = ctx.pathParam("id");
        ProxyListener listener = gson.fromJson(ctx.body(), ProxyListener.class);
        if (listener == null || listener.getBindAddress() == null || listener.getPort() <= 0) {
            ctx.status(400);
            ctx.json(pwnService.apiError("listener", "Invalid bind address or port"));
            return;
        }
        boolean success = pwnService.updateProxyListener(id, listener.getBindAddress(), listener.getPort());
        if (success) {
            ctx.status(200);
            ctx.json(listener);
        } else {
            ctx.status(404);
            ctx.json(pwnService.apiError("listener", "Proxy listener not found or update unsupported in Montoya API"));
        }
    }

    @OpenApi(
            summary = "Delete a proxy listener",
            operationId = "deleteProxyListener",
            path = "/proxy/listeners/{id}",
            methods = {HttpMethod.DELETE},
            pathParams = {@OpenApiParam(name = "id", description = "ID of the proxy listener", required = true)},
            responses = {
                    @OpenApiResponse(status = "204", description = "Proxy listener deleted"),
                    @OpenApiResponse(status = "404", description = "Proxy listener not found", content = {@OpenApiContent(from = ApiResponse.class)})
            }
    )
    private void deleteProxyListener(Context ctx) {
        String id = ctx.pathParam("id");
        boolean success = pwnService.deleteProxyListener(id);
        if (success) {
            ctx.status(204);
            ctx.result("");
        } else {
            ctx.status(404);
            ctx.json(pwnService.apiError("listener", "Proxy listener not found or deletion unsupported in Montoya API"));
        }
    }
}
