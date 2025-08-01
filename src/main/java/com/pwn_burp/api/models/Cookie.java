package com.pwn_burp.api.models;

public class Cookie {
    public String domain;
    public String expiration;
    public String path;
    public String name;
    public String value;

    public Cookie(String domain, String expiration, String path, String name, String value) {
        this.domain = domain;
        this.expiration = expiration;
        this.path = path;
        this.name = name;
        this.value = value;
    }
}
