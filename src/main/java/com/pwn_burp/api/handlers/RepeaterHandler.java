package com.pwn_burp.api.handlers;

import com.google.gson.Gson;
import com.pwn_burp.api.models.ApiResponse;
import com.pwn_burp.api.models.RepeaterItem;
import com.pwn_burp.api.models.RepeaterMessage;
import com.pwn_burp.api.models.RepeaterResponse;
import com.pwn_burp.burp.PwnService;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;

import java.util.List;

public class RepeaterHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public RepeaterHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/repeater", this::getAll);
        server.get("/repeater/{id}", this::getOne);
        server.post("/repeater", this::create);
        server.put("/repeater/{id}", this::update);
        server.delete("/repeater/{id}", this::deleteOne);
        server.post("/repeater/{id}/send", this::send);
    }

    @OpenApi(
        summary = "Get all repeater items",
        operationId = "getAllRepeaterItems",
        path = "/repeater",
        methods = {HttpMethod.GET},
        responses = {
            @OpenApiResponse(status = "200", content = {@OpenApiContent(from = RepeaterItem[].class)})
        }
    )
    private void getAll(Context ctx) {
        List<RepeaterItem> items = pwnService.getRepeaterItems();
        ctx.status(200);
        ctx.json(items);
    }

    @OpenApi(
        summary = "Get a specific repeater item",
        operationId = "getRepeaterItem",
        path = "/repeater/{id}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "id", type = Integer.class, required = true)},
        responses = {
            @OpenApiResponse(status = "200", content = {@OpenApiContent(from = RepeaterItem.class)}),
            @OpenApiResponse(status = "404", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void getOne(Context ctx) {
        int id;
        try {
            id = Integer.parseInt(ctx.pathParam("id"));
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid ID"));
            return;
        }
        RepeaterItem item = pwnService.getRepeaterItem(id);
        if (item == null) {
            ctx.status(404);
            ctx.json(pwnService.apiError("id", "Repeater item not found"));
            return;
        }
        ctx.status(200);
        ctx.json(item);
    }

    @OpenApi(
        summary = "Create a new repeater item",
        operationId = "createRepeaterItem",
        path = "/repeater",
        methods = {HttpMethod.POST},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = RepeaterMessage.class)}),
        responses = {
            @OpenApiResponse(status = "201", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "400", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void create(Context ctx) {
        RepeaterMessage msg = gson.fromJson(ctx.body(), RepeaterMessage.class);
        if (msg == null || msg.name == null || msg.request == null) {
            ctx.status(400);
            ctx.json(pwnService.apiError("body", "Missing name or request"));
            return;
        }
        int id = pwnService.createRepeaterItem(msg.name, msg.request);
        ctx.status(201);
        ctx.json(new ApiResponse("id", id));
    }

    @OpenApi(
        summary = "Update a repeater item",
        operationId = "updateRepeaterItem",
        path = "/repeater/{id}",
        methods = {HttpMethod.PUT},
        pathParams = {@OpenApiParam(name = "id", type = Integer.class, required = true)},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = RepeaterMessage.class)}),
        responses = {
            @OpenApiResponse(status = "200", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "400", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "404", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void update(Context ctx) {
        int id;
        try {
            id = Integer.parseInt(ctx.pathParam("id"));
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid ID"));
            return;
        }
        RepeaterMessage msg = gson.fromJson(ctx.body(), RepeaterMessage.class);
        if (msg == null || (msg.name == null && msg.request == null)) {
            ctx.status(400);
            ctx.json(pwnService.apiError("body", "Nothing to update"));
            return;
        }
        boolean updated = pwnService.updateRepeaterItem(id, msg.name, msg.request);
        if (!updated) {
            ctx.status(404);
            ctx.json(pwnService.apiError("id", "Repeater item not found"));
            return;
        }
        ctx.status(200);
        ctx.json(new ApiResponse("success", true));
    }

    @OpenApi(
        summary = "Delete a repeater item",
        operationId = "deleteRepeaterItem",
        path = "/repeater/{id}",
        methods = {HttpMethod.DELETE},
        pathParams = {@OpenApiParam(name = "id", type = Integer.class, required = true)},
        responses = {
            @OpenApiResponse(status = "204"),
            @OpenApiResponse(status = "404", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void deleteOne(Context ctx) {
        int id;
        try {
            id = Integer.parseInt(ctx.pathParam("id"));
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid ID"));
            return;
        }
        boolean deleted = pwnService.deleteRepeaterItem(id);
        if (!deleted) {
            ctx.status(404);
            ctx.json(pwnService.apiError("id", "Repeater item not found"));
            return;
        }
        ctx.status(204);
    }

    @OpenApi(
        summary = "Send a repeater item and retrieve the response",
        operationId = "sendRepeaterItem",
        path = "/repeater/{id}/send",
        methods = {HttpMethod.POST},
        pathParams = {@OpenApiParam(name = "id", type = Integer.class, required = true)},
        responses = {
            @OpenApiResponse(status = "200", content = {@OpenApiContent(from = RepeaterResponse.class)}),
            @OpenApiResponse(status = "404", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "500", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void send(Context ctx) {
        int id;
        try {
            id = Integer.parseInt(ctx.pathParam("id"));
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid ID"));
            return;
        }
        RepeaterResponse resp;
        try {
            resp = pwnService.sendRepeaterItem(id);
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("request", e.getMessage()));
            return;
        } catch (Exception e) {
            ctx.status(500);
            ctx.json(pwnService.apiError("error", e.getMessage()));
            return;
        }
        if (resp == null) {
            ctx.status(404);
            ctx.json(pwnService.apiError("id", "Repeater item not found"));
            return;
        }
        ctx.status(200);
        ctx.json(resp);
    }
}
