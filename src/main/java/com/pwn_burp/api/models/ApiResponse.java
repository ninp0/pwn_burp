package com.pwn_burp.api.models;

public class ApiResponse {
    public String field;
    public Object value;

    public ApiResponse(String field, Object value) {
        this.field = field;
        this.value = value;
    }
}
