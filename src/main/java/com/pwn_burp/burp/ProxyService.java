package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import com.google.gson.*;
import com.pwn_burp.api.models.ProxyListener;
import com.pwn_burp.api.models.ProxyHistoryMessage;
import java.util.*;

public class ProxyService {
    private final MontoyaApi api;
    private final Map<Integer, ProxyHistoryMessage> items = new HashMap<>();
    private final IBurpExtenderCallbacks callbacks;
    private final Gson gson = new Gson();

    public ProxyService(MontoyaApi api, IBurpExtenderCallbacks callbacks) {
        this.api = api;
        this.callbacks = callbacks;
        if (this.callbacks == null) {
            throw new IllegalArgumentException("IBurpExtenderCallbacks cannot be null");
        }
    }

    public String getProxyHistory(String urlPrefix) {
        JsonArray maps = new JsonArray();
        api.proxy().history().forEach(item -> {
            if (urlPrefix.isEmpty() || (item.request() != null && item.request().url() != null && item.request().url().startsWith(urlPrefix))) {
                JsonObject obj = new JsonObject();

                Integer id = item.id() - 1; // Adjusting to zero-based index
                obj.addProperty("id", id != null ? id : -1);

                String requestBase64 = item.request() != null ? Base64.getEncoder().encodeToString(item.request().toByteArray().getBytes()) : null;
                obj.addProperty("request", requestBase64);

                String responseBase64 = item.response() != null ? Base64.getEncoder().encodeToString(item.response().toByteArray().getBytes()) : null;
                obj.addProperty("response", responseBase64);

                String highlight = item.annotations() != null && item.annotations().highlightColor() != null ? item.annotations().highlightColor().toString() : "";
                obj.addProperty("highlight", highlight);

                String comment = item.annotations() != null && item.annotations().notes() != null ? item.annotations().notes() : "";
                obj.addProperty("comment", comment);

                JsonObject serviceObj = new JsonObject();
                HttpService httpService = item.httpService();
                serviceObj.addProperty("host", httpService != null && httpService.host() != null ? httpService.host() : "");
                serviceObj.addProperty("port", httpService != null ? httpService.port() : 0);
                serviceObj.addProperty("protocol", httpService != null ? (httpService.secure() ? "https" : "http") : "");
                obj.add("http_service", serviceObj);
                maps.add(obj);
            }
        });

        return maps.toString();
    }

    public void updateProxyHistoryEntry(int id, String notes, String color) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (id < 0 || id >= history.size()) {
            api.logging().logToError("Invalid proxy history id: " + id);
            return;
        }
        ProxyHttpRequestResponse entry = history.get(id);
        HighlightColor hl = HighlightColor.NONE;
        if (color != null) {
            try {
                hl = HighlightColor.valueOf(color.toUpperCase());
            } catch (IllegalArgumentException e) {
                api.logging().logToError("Invalid highlight color: " + color + ". Using NONE.");
                hl = HighlightColor.NONE;
            }
        }
        Annotations annotations = entry.annotations();
        annotations.setNotes(notes);
        annotations.setHighlightColor(hl);
    }

    public String getWebSocketHistory(String urlPrefix) {
        JsonArray maps = new JsonArray();
        api.proxy().webSocketHistory().forEach(item -> {
            // Montoya API provides payload() (ByteArray) for the message contents and opcode()
            JsonObject obj = new JsonObject();

            int id = item.id(); // Use Montoya's id directly
            obj.addProperty("id", id);

            obj.addProperty("web_socket_id", item.webSocketId());
            obj.addProperty("direction", item.direction() != null ? item.direction().toString() : "");

            // URL retrieval
            /*
            String wsUrl = "";
            try {
                if (item.webSocket() != null && item.webSocket().handshakeRequest() != null) {
                    wsUrl = item.webSocket().handshakeRequest().url();
                } else if (item.webSocket() != null && item.webSocket().httpService() != null) {
                    HttpService hs = item.webSocket().httpService();
                    wsUrl = (hs.secure() ? "wss" : "ws") + "://" + hs.host() + (hs.port() > 0 ? ":" + hs.port() : "");
                }
            } catch (Exception ignored) {}
            obj.addProperty("url", wsUrl);
            */

            String payloadBase64 = item.payload() != null
                    ? Base64.getEncoder().encodeToString(item.payload().getBytes())
                    : null;
            obj.addProperty("payload", payloadBase64);

            String highlight = (item.annotations() != null && item.annotations().highlightColor() != null)
                    ? item.annotations().highlightColor().toString()
                    : "";
            obj.addProperty("highlight", highlight);

            String comment = (item.annotations() != null && item.annotations().notes() != null)
                    ? item.annotations().notes()
                    : "";
            obj.addProperty("comment", comment);

            maps.add(obj);
        });
        return maps.toString();
    }
 
    public void updateWebSocketHistoryEntry(int id, String notes, String color) {
        List<ProxyWebSocketMessage> history = api.proxy().webSocketHistory();
        if (id < 0 || id >= history.size()) {
            api.logging().logToError("Invalid proxy history id: " + id);
            return;
        }
        ProxyWebSocketMessage entry = history.get(id);
        HighlightColor hl = HighlightColor.NONE;
        if (color != null) {
            try {
                hl = HighlightColor.valueOf(color.toUpperCase());
            } catch (IllegalArgumentException e) {
                api.logging().logToError("Invalid highlight color: " + color + ". Using NONE.");
                hl = HighlightColor.NONE;
            }
        }
        Annotations annotations = entry.annotations();
        annotations.setNotes(notes);
        annotations.setHighlightColor(hl);
    }

    public void setProxyInterceptionEnabled(boolean enabled) {
        if (enabled) {
            api.proxy().enableIntercept();
        } else {
            api.proxy().disableIntercept();
        }
    }

    public List<ProxyListener> getProxyListeners() {
        try {
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listenersArray = proxy.getAsJsonArray("request_listeners");
            List<ProxyListener> listeners = new ArrayList<>();
            for (int i = 0; i < listenersArray.size(); i++) {
                JsonObject listenerJson = listenersArray.get(i).getAsJsonObject();
                String listenMode = listenerJson.get("listen_mode").getAsString();
                String bindAddress;
                if ("all_interfaces".equals(listenMode)) {
                    bindAddress = "*";
                } else if ("loopback_only".equals(listenMode)) {
                    bindAddress = "127.0.0.1";
                } else {
                    bindAddress = listenerJson.get("bindAddress").getAsString();
                }
                int port = listenerJson.get("listener_port").getAsInt();
                boolean enabled = listenerJson.get("running").getAsBoolean();
                listeners.add(new ProxyListener(String.valueOf(i), bindAddress, port, enabled));
            }
            return listeners;
        } catch (Exception e) {
            api.logging().logToError("Failed to get proxy listeners: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public boolean addProxyListener(String bindAddress, int port) {
        try {
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listeners = proxy.getAsJsonArray("request_listeners");
            JsonObject newListener = new JsonObject();
            String mode;
            if ("*".equals(bindAddress)) {
                mode = "all_interfaces";
            } else if ("127.0.0.1".equals(bindAddress)) {
                mode = "loopback_only";
            } else {
                mode = "specific_address";
                newListener.addProperty("bindAddress", bindAddress);
            }
            newListener.addProperty("listen_mode", mode);
            newListener.addProperty("listener_port", port);
            newListener.addProperty("running", true);
            newListener.addProperty("certificate_mode", "per_host");
            listeners.add(newListener);
            callbacks.loadConfigFromJson(root.toString());
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to add proxy listener: " + e.getMessage());
            return false;
        }
    }

    public boolean updateProxyListener(String id, String bindAddress, int port) {
        try {
            int index = Integer.parseInt(id);
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listeners = proxy.getAsJsonArray("request_listeners");
            if (index < 0 || index >= listeners.size()) {
                return false;
            }
            JsonObject listener = listeners.get(index).getAsJsonObject();
            String mode;
            if ("*".equals(bindAddress)) {
                mode = "all_interfaces";
            } else if ("127.0.0.1".equals(bindAddress)) {
                mode = "loopback_only";
            } else {
                mode = "specific_address";
                listener.addProperty("bindAddress", bindAddress);
            }
            listener.addProperty("listen_mode", mode);
            listener.addProperty("listener_port", port);
            callbacks.loadConfigFromJson(root.toString());
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to update proxy listener: " + e.getMessage());
            return false;
        }
    }

    public boolean deleteProxyListener(String id) {
        try {
            int index = Integer.parseInt(id);
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listeners = proxy.getAsJsonArray("request_listeners");
            if (index < 0 || index >= listeners.size()) {
                return false;
            }
            listeners.remove(index);
            callbacks.loadConfigFromJson(root.toString());
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to delete proxy listener: " + e.getMessage());
            return false;
        }
    }
}
