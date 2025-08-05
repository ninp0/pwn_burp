package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;

public class SpiderResponse {
    @SerializedName("id")
    public int id;

    public SpiderResponse(int id) {
        this.id = id;
    }
}
