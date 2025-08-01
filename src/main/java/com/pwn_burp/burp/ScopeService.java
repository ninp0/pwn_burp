package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import java.net.URL;

public class ScopeService {
    private final MontoyaApi api;

    public ScopeService(MontoyaApi api) {
        this.api = api;
    }

    public boolean isInScope(URL url) {
        return api.scope().isInScope(url.toString());
    }

    public void includeInScope(URL url) {
        api.scope().includeInScope(url.toString());
    }

    public void excludeFromScope(URL url) {
        api.scope().excludeFromScope(url.toString());
    }
}
