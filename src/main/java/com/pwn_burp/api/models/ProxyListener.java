package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;

public class ProxyListener {
    @SerializedName("id")
    private final String id; // Unique identifier for the listener (e.g., bind address + port)
    @SerializedName("bind_address")
    private final String bindAddress;
    @SerializedName("port")
    private final int port;
    @SerializedName("enabled")
    private final boolean enabled;

    public ProxyListener(String id, String bindAddress, int port, boolean enabled) {
        this.id = id;
        this.bindAddress = bindAddress;
        this.port = port;
        this.enabled = enabled;
    }

    public String getId() {
        return id;
    }

    public String getBindAddress() {
        return bindAddress;
    }

    public int getPort() {
        return port;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
