package com.pwn_burp.api.handlers;

import com.google.gson.*;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;

import java.util.Base64;

public class SiteMapHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public SiteMapHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/sitemap", this::getAllSiteMap);
        server.get("/sitemap/{url}", this::getSiteMapByUrl);
        server.post("/sitemap", this::addToSiteMap);
        server.put("/sitemap", this::updateSiteMap);
    }

    @OpenApi(
        summary = "Get all site map entries",
        operationId = "getAllSiteMap",
        path = "/sitemap",
        methods = {HttpMethod.GET},
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "List of site map entries",
                content = {
                    @OpenApiContent(
                        from = SiteMapMessage[].class,
                        mimeType = "application/json",
                        example = "[{\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example sitemap entry\",\n" +
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
    private void getAllSiteMap(Context ctx) {
        ctx.status(200);
        ctx.json(pwnService.getSiteMap(""));
    }

    @OpenApi(
        summary = "Get site map entries for a specific Base64 Encoded URL",
        operationId = "getSiteMapByUrl",
        path = "/sitemap/{url}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "url", description = "Base64-encoded URL prefix", required = true)},
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "List of site map entries",
                content = {
                    @OpenApiContent(
                        from = SiteMapMessage[].class,
                        mimeType = "application/json",
                        example = "[{\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example sitemap entry\",\n" +
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
    private void getSiteMapByUrl(Context ctx) {
        String url = new String(Base64.getDecoder().decode(ctx.pathParam("url") != null ? ctx.pathParam("url") : ""));
        ctx.status(200);
        ctx.json(pwnService.getSiteMap(url));
    }

    @OpenApi(
        summary = "Add an entry to the site map",
        operationId = "addToSiteMap",
        path = "/sitemap",
        methods = {HttpMethod.POST},
        requestBody = @OpenApiRequestBody(
            content = {
                @OpenApiContent(
                    from = SiteMapMessage.class,
                    mimeType = "application/json",
                    example = "{\n" +
                              "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                              "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                              "  \"highlight\": \"BLUE\",\n" +
                              "  \"comment\": \"Example sitemap entry\",\n" +
                              "  \"http_service\": {\n" +
                              "    \"host\": \"example.com\",\n" +
                              "    \"port\": 443,\n" +
                              "    \"protocol\": \"https\"\n" +
                              "  }\n" +
                              "}"
                )
            }
        ),
        responses = {
            @OpenApiResponse(
                status = "201",
                description = "Site map entry added",
                content = {
                    @OpenApiContent(
                        from = SiteMapMessage.class,
                        mimeType = "application/json",
                        example = "{\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example sitemap entry\",\n" +
                                  "  \"http_service\": {\n" +
                                  "    \"host\": \"example.com\",\n" +
                                  "    \"port\": 443,\n" +
                                  "    \"protocol\": \"https\"\n" +
                                  "  }\n" +
                                  "}"
                    )
                }
            ),
            @OpenApiResponse(
                status = "400",
                description = "Invalid request",
                content = {
                    @OpenApiContent(
                        from = ApiResponse.class,
                        mimeType = "application/json",
                        example = "{\"error\": \"SiteMapMessage, request, or http_service cannot be null or invalid Base64\"}"
                    )
                }
            )
        }
    )
    private void addToSiteMap(Context ctx) {
        SiteMapMessage message = gson.fromJson(ctx.body(), SiteMapMessage.class);
        pwnService.addToSiteMap(message);
        ctx.status(201);
        ctx.json(message);
    }

    @OpenApi(
        summary = "Update an entry to the site map",
        operationId = "updateSiteMap",
        path = "/sitemap",
        methods = {HttpMethod.PUT},
        requestBody = @OpenApiRequestBody(
            content = {
                @OpenApiContent(
                    from = SiteMapMessage.class,
                    mimeType = "application/json",
                    example = "{\n" +
                              "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                              "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                              "  \"highlight\": \"BLUE\",\n" +
                              "  \"comment\": \"Example sitemap entry\",\n" +
                              "  \"http_service\": {\n" +
                              "    \"host\": \"example.com\",\n" +
                              "    \"port\": 443,\n" +
                              "    \"protocol\": \"https\"\n" +
                              "  }\n" +
                              "}"
                )
            }
        ),
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "Site map entry updated",
                content = {
                    @OpenApiContent(
                        from = SiteMapMessage.class,
                        mimeType = "application/json",
                        example = "{\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example sitemap entry\",\n" +
                                  "  \"http_service\": {\n" +
                                  "    \"host\": \"example.com\",\n" +
                                  "    \"port\": 443,\n" +
                                  "    \"protocol\": \"https\"\n" +
                                  "  }\n" +
                                  "}"
                    )
                }
            ),
            @OpenApiResponse(
                status = "400",
                description = "Invalid request",
                content = {
                    @OpenApiContent(
                        from = ApiResponse.class,
                        mimeType = "application/json",
                        example = "{\"error\": \"SiteMapMessage, request, or http_service cannot be null or invalid Base64\"}"
                    )
                }
            )
        }
    )
    private void updateSiteMap(Context ctx) {
        SiteMapMessage message = gson.fromJson(ctx.body(), SiteMapMessage.class);
        pwnService.updateSiteMap(message);
        ctx.status(200);
        ctx.json(message);
    }
}
