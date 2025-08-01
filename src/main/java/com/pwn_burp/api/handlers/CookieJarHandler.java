package com.pwn_burp.api.handlers;

import com.google.gson.Gson;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.openapi.*;

public class CookieJarHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public CookieJarHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/jar", this::getCookieJar);
        server.post("/jar", this::updateCookieJar);
    }

    @OpenApi(
            summary = "Get cookie jar (not supported)",
            operationId = "getCookieJar",
            path = "/jar",
            methods = {HttpMethod.GET},
            responses = {
                    @OpenApiResponse(status = "200", description = "Empty list (cookie jar not supported)", content = {@OpenApiContent(type = "application/json")})
            }
    )
    private void getCookieJar(Context ctx) {
        ctx.status(200);
        ctx.json("[]");
    }

    @OpenApi(
            summary = "Update cookie jar (not supported)",
            operationId = "updateCookieJar",
            path = "/jar",
            methods = {HttpMethod.POST},
            requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = Cookie.class)}),
            responses = {
                    @OpenApiResponse(status = "201", description = "Cookie jar update attempted", content = {@OpenApiContent(from = Cookie.class)})
            }
    )
    private void updateCookieJar(Context ctx) {
        Cookie cookie = gson.fromJson(ctx.body(), Cookie.class);
        pwnService.updateCookieJar(cookie);
        ctx.status(201);
        ctx.json(cookie);
    }
}
