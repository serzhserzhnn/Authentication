package com.example.service;

public interface SendService {
    String USER_REMOVE_TOPIC = "removeUserList";

    void sendUserRemove(String action, String id);
}
