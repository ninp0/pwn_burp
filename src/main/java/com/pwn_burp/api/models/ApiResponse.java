package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;

public class ApiResponse {
    @SerializedName("field")
    public String field;
    @SerializedName("value")
    public Object value;

    public ApiResponse(String field, Object value) {
        this.field = field;
        this.value = value;
    }
}
