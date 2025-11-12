package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.Objects;

public class WebSocketHistoryMessage {
    @SerializedName("id")
    private final int id; // Unique identifier for the message

    @SerializedName("url")
    private final String url; 

    @SerializedName("direction")
    private final String direction;

    @SerializedName("message")
    private final String message; // Base64-encoded HTTP response

    @SerializedName("highlight")
    private String highlight;

    @SerializedName("comment")
    private String comment;

    @SerializedName("web_socket_id")
    private final int webSocketId;

    public WebSocketHistoryMessage(int id, String url, String direction, String message, String highlight, String comment, int web_socket_id) {
        this.id = id;
        this.url = url;
        this.direction = direction;
        this.message = message;
        this.highlight = highlight;
        this.comment = comment;
        this.webSocketId = web_socket_id;
    }

    public int getId() {
        return id;
    }

    public String getComment() {
	return comment;
    }

    public void setComment(String comment) {
	this.comment = comment;
    }

    public String getHighlight() {
	return highlight;
    }

    public void setHighlight(String highlight) {
	this.highlight = highlight;
    }

    @Override
    public boolean equals(Object o) {
	if (this == o) return true;
	if (o == null || getClass() != o.getClass()) return false;
	WebSocketHistoryMessage that = (WebSocketHistoryMessage) o;
	return id == that.id &&
	       Objects.equals(url, that.url) &&
	       Objects.equals(direction, that.direction) &&
	       Objects.equals(message, that.message) &&
	       Objects.equals(highlight, that.highlight) &&
	       Objects.equals(comment, that.comment) &&
	       webSocketId == that.webSocketId;
    }

    @Override
    public String toString() {
        return "WebSocketHistoryMessage{"+
               "  id=" + id + '\'' +
	       ", url='" + url + '\'' +
	       ", direction='" + direction + '\'' +
	       ", message='" + message + '\'' +
	       ", highlight='" + highlight + '\'' +
	       ", comment='" + comment + '\'' +
	       ", web_socket_id=" + webSocketId +
               '}';
    }
}
