package com.pwn_burp.api.handlers;

import com.google.gson.*;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;

import java.util.Base64;

public class ProxyHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public ProxyHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/proxy/history", this::getProxyHistory);
        server.get("/websocket/history", this::getWebSocketHistory);
        server.get("/proxy/history/{url}", this::getProxyHistoryByUrl);
        server.put("/proxy/history/{id}", this::updateProxyHistoryEntry);
        server.put("/websocket/history/{id}", this::updateWebSocketHistoryEntry);
        server.post("/proxy/intercept/enable", this::enableProxyIntercept);
        server.post("/proxy/intercept/disable", this::disableProxyIntercept);
        server.get("/proxy/listeners", this::getProxyListeners);
        server.post("/proxy/listeners", this::addProxyListener);
        server.put("/proxy/listeners/{id}", this::updateProxyListener);
        server.delete("/proxy/listeners/{id}", this::deleteProxyListener);
    }

    @OpenApi(
        summary = "Get proxy history (paginated)",
        operationId = "getProxyHistory",
        path = "/proxy/history",
        methods = {HttpMethod.GET},
        queryParams = {
            @OpenApiParam(
                name = "limit",
                description = "Maximum number of items to return (capped at 500)",
                required = false,
                type = Integer.class,
                example = "200"
            ),
            @OpenApiParam(
                name = "offset",
                description = "Number of items to skip (for pagination)",
                required = false,
                type = Integer.class,
                example = "0"
            )
        },
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "List of proxy history entries",
                content = {
                    @OpenApiContent(
                        from = ProxyHistoryMessage[].class,
                        mimeType = "application/json",
                        example = "[{\n" +
                                  "  \"id\": 0,\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example proxy history entry\",\n" +
                                  "  \"http_service\": {\n" +
                                  "    \"host\": \"example.com\",\n" +
                                  "    \"port\": 443,\n" +
                                  "    \"protocol\": \"https\"\n" +
                                  "  }\n" +
                                  "}]"
                    )
                }
            )
        }
    )
    private void getProxyHistory(Context ctx) {
        String urlPrefix = "";
        int limit  = ctx.queryParamAsClass("limit", Integer.class).getOrDefault(200);
        int offset = ctx.queryParamAsClass("offset", Integer.class).getOrDefault(0);

        ctx.status(200);
        ctx.json(pwnService.getProxyHistory(urlPrefix, limit, offset));
    }

    @OpenApi(
        summary = "Get proxy history entries for a specific Base64-encoded URL (paginated)",
        operationId = "getProxyHistoryByUrl",
        path = "/proxy/history/{url}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "url", description = "Base64-encoded URL prefix", required = true)},
        queryParams = {
            @OpenApiParam(
                name = "limit",
                description = "Maximum number of items to return (capped at 500)",
                required = false,
                type = Integer.class,
                example = "200"
            ),
            @OpenApiParam(
                name = "offset",
                description = "Number of items to skip (for pagination)",
                required = false,
                type = Integer.class,
                example = "0"
            )
        },
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "List of proxy history entries",
                content = {
                    @OpenApiContent(
                        from = ProxyHistoryMessage[].class,
                        mimeType = "application/json",
                        example = "[{\n" +
                                  "  \"id\": 0,\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example proxy history entry\",\n" +
                                  "  \"http_service\": {\n" +
                                  "    \"host\": \"example.com\",\n" +
                                  "    \"port\": 443,\n" +
                                  "    \"protocol\": \"https\"\n" +
                                  "  }\n" +
                                  "}]"
                    )
                }
            )
        }
    )
    private void getProxyHistoryByUrl(Context ctx) {
        String urlPrefix = new String(Base64.getDecoder().decode(ctx.pathParam("url") != null ? ctx.pathParam("url") : ""));
        int limit  = ctx.queryParamAsClass("limit", Integer.class).getOrDefault(200);
        int offset = ctx.queryParamAsClass("offset", Integer.class).getOrDefault(0);

        ctx.status(200);
        ctx.json(pwnService.getProxyHistory(urlPrefix, limit, offset));
    }

    // === The rest of the file stays EXACTLY the same (no other changes) ===
    @OpenApi(
        summary = "Get WebSocket history",
        operationId = "getWebSocketHistory",
        path = "/websocket/history",
        methods = {HttpMethod.GET},
        responses = {
        @OpenApiResponse(
            status = "200",
            description = "List of WebSocket history entries",
            content = {
            @OpenApiContent(
                from = WebSocketHistoryMessage[].class,
                mimeType = "application/json",
                example = "[{\n" +
                      "  \"id\": 0,\n" +
                          "  \"url\": \"wss://example.com/socket\",\n" +
                                      "  \"direction\": \"to_server\",\n" +
                      "  \"message\": \"SGVsbG8gd29ybGQh\",\n" +
                      "  \"highlight\": \"GREEN\",\n" +
                      "  \"comment\": \"Example WebSocket message\",\n" +
                      "  \"web_socket_id\": 1\n" +
                      "}]"
            )
            }
        )
        }
    )
    private void getWebSocketHistory(Context ctx) {
    ctx.status(200);
    ctx.json(pwnService.getWebSocketHistory(""));
    }

    @OpenApi(
        summary = "Update annotations for a proxy history entry",
        operationId = "updateProxyHistoryEntry",
        path = "/proxy/history/{id}",
        methods = {HttpMethod.PUT},
        pathParams = {@OpenApiParam(name = "id", description = "ID of the proxy history entry", required = true)},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = ProxyHistoryMessage.class)}),
        responses = {
            @OpenApiResponse(status = "200", description = "Annotation updated successfully", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "400", description = "Invalid parameters", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void updateProxyHistoryEntry(Context ctx) {
        ProxyHistoryMessage msg = gson.fromJson(ctx.body(), ProxyHistoryMessage.class);
        if (msg == null || msg.getId() < 0 || msg.getComment() == null) {
            ctx.status(400);
            ctx.json(pwnService.apiError("parameters", "Invalid parameters: index must be non-negative and notes must be provided"));
            return;
        }
        pwnService.updateProxyHistoryEntry(msg.getId(), msg.getComment(), msg.getHighlight());
        ctx.status(200);
        ctx.json(new ApiResponse("success", "Proxy history entry updated"));
    }

    @OpenApi(
        summary = "Update annotations for a WebSocket history entry",
        operationId = "updateWebSocketHistoryEntry",
        path = "/websocket/history/{id}",
        methods = {HttpMethod.PUT},
        pathParams = {@OpenApiParam(name = "id", description = "ID of the WebSocket history entry", required = true)},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = WebSocketHistoryMessage.class)}),
        responses = {
            @OpenApiResponse(status = "200", description = "Annotation updated successfully", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "400", description = "Invalid parameters", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void updateWebSocketHistoryEntry(Context ctx) {
        // TODO: implement if needed (stub)
        ctx.status(200);
        ctx.json(new ApiResponse("success", "WebSocket history entry updated (stub)"));
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
        ctx.json(new ApiResponse("success", "Proxy interception enabled"));
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
        ctx.json(new ApiResponse("success", "Proxy interception disabled"));
    }

    @OpenApi(
        summary = "Get proxy listeners",
        operationId = "getProxyListeners",
        path = "/proxy/listeners",
        methods = {HttpMethod.GET},
        responses = {
            @OpenApiResponse(status = "200", description = "List of proxy listeners")
        }
    )
    private void getProxyListeners(Context ctx) {
        ctx.status(200);
        ctx.json(pwnService.getProxyListeners());
    }

    @OpenApi(
        summary = "Add a proxy listener",
        operationId = "addProxyListener",
        path = "/proxy/listeners",
        methods = {HttpMethod.POST},
        responses = {
            @OpenApiResponse(status = "200", description = "Listener added")
        }
    )
    private void addProxyListener(Context ctx) {
        // TODO: implement if needed
        ctx.status(200);
        ctx.json(new ApiResponse("success", "Proxy listener added (stub)"));
    }

    @OpenApi(
        summary = "Update a proxy listener",
        operationId = "updateProxyListener",
        path = "/proxy/listeners/{id}",
        methods = {HttpMethod.PUT},
        pathParams = {@OpenApiParam(name = "id", description = "ID of the listener", required = true)},
        responses = {
            @OpenApiResponse(status = "200", description = "Listener updated")
        }
    )
    private void updateProxyListener(Context ctx) {
        // TODO: implement if needed
        ctx.status(200);
        ctx.json(new ApiResponse("success", "Proxy listener updated (stub)"));
    }

    @OpenApi(
        summary = "Delete a proxy listener",
        operationId = "deleteProxyListener",
        path = "/proxy/listeners/{id}",
        methods = {HttpMethod.DELETE},
        pathParams = {@OpenApiParam(name = "id", description = "ID of the listener", required = true)},
        responses = {
            @OpenApiResponse(status = "200", description = "Listener deleted")
        }
    )
    private void deleteProxyListener(Context ctx) {
        // TODO: implement if needed
        ctx.status(200);
        ctx.json(new ApiResponse("success", "Proxy listener deleted (stub)"));
    }
}
