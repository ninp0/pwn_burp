package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import com.google.gson.*;
import com.pwn_burp.api.models.ProxyListener;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ProxyService {
    private final MontoyaApi api;
    private final IBurpExtenderCallbacks callbacks;
    private final Gson gson = new Gson();

    public ProxyService(MontoyaApi api, IBurpExtenderCallbacks callbacks) {
        this.api = api;
        this.callbacks = callbacks;
        if (this.callbacks == null) {
            throw new IllegalArgumentException("IBurpExtenderCallbacks cannot be null");
        }
    }

    public String getProxyHistory() {
        JsonArray history = new JsonArray();
        api.proxy().history().forEach(item -> {
            JsonObject obj = new JsonObject();
            String requestBase64 = item.request() != null ? Base64.getEncoder().encodeToString(item.request().toByteArray().getBytes()) : null;
            obj.addProperty("request", requestBase64);
            String responseBase64 = item.response() != null ? Base64.getEncoder().encodeToString(item.response().toByteArray().getBytes()) : null;
            obj.addProperty("response", responseBase64);
            history.add(obj);
        });
        return history.toString();
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
                    bindAddress = listenerJson.get("bind_address").getAsString();
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
                newListener.addProperty("bind_address", bindAddress);
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
                listener.addProperty("bind_address", bindAddress);
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
