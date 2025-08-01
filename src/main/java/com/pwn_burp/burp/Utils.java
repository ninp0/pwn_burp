package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.scanner.audit.issues.*;
import burp.api.montoya.http.HttpService;
import com.google.gson.*;
import java.net.*;
import java.util.*;

public class Utils {
    public static JsonObject apiError(String field, String message) {
        JsonObject error = new JsonObject();
        error.addProperty("field", field != null ? field : "error");
        error.addProperty("message", message != null ? message : "Unknown error");
        return error;
    }

    public static boolean isNotSameOrigin(String host, String origin) {
        if (origin == null || origin.isEmpty()) {
            return false;
        }
        try {
            URL urlOrigin = new URI(origin).toURL();
            return !host.equals(urlOrigin.getAuthority());
        } catch (URISyntaxException | MalformedURLException e) {
            return true;
        }
    }

    public static JsonArray scanIssuesToJsonArray(AuditIssue[] issues) {
        JsonArray array = new JsonArray();
        for (AuditIssue issue : issues) {
            JsonObject obj = new JsonObject();
            obj.addProperty("name", issue.name());
            obj.addProperty("severity", issue.severity().name());
            obj.addProperty("confidence", issue.confidence().name());
            obj.addProperty("host", issue.httpService() != null ? issue.httpService().host() : "");
            obj.addProperty("url", issue.baseUrl() != null ? issue.baseUrl().toString() : "");
            array.add(obj);
        }
        return array;
    }
}
