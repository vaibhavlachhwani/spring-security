package com.vaibhav.springsecurity.entities;

import java.time.LocalDateTime;

public class Message {
    private int id;
    private String user;
    private LocalDateTime timestamp;
    private String text;

    public Message() {}

    public Message(int id, String user, LocalDateTime timestamp, String text) {
        this.id = id;
        this.user = user;
        this.timestamp = timestamp;
        this.text = text;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Message{");
        sb.append("id=").append(id);
        sb.append(", timestamp=").append(timestamp);
        sb.append(", text='").append(text).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
