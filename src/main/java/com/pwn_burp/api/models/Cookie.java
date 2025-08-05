package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;

public class Cookie {
    @SerializedName("domain")
    public String domain;
    @SerializedName("expiration")
    public String expiration;
    @SerializedName("path")
    public String path;
    @SerializedName("name")
    public String name;
    @SerializedName("value")
    public String value;

    public Cookie(String domain, String expiration, String path, String name, String value) {
        this.domain = domain;
        this.expiration = expiration;
        this.path = path;
        this.name = name;
        this.value = value;
    }
}
