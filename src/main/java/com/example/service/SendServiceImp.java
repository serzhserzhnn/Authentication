package com.example.service;

import com.example.jms.Producer;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SendServiceImp implements com.example.service.SendService {

    private final Producer producer;

    @Autowired
    public SendServiceImp(Producer producer) {
        this.producer = producer;
    }

    @Override
    public void sendUserRemove(String action, String id) {

        JSONObject message = new JSONObject();
        message.put("operation", action);
        message.put("id", id);

        producer.sendMessage(USER_REMOVE_TOPIC, message.toJSONString());
    }
}
