package com.vendo.auth_service.adapter.code.in.messaging.kafka.producer;

import com.vendo.auth_service.port.code.CodeEmailNotificationPort;
import com.vendo.event_lib.code.EmailCodeEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
class CodeEmailEventProducer implements CodeEmailNotificationPort {

    @Value("${kafka.events.notification.email-event.topic}")
    private String emailEventTopic;

    private final KafkaTemplate<String, EmailCodeEvent> kafkaTemplate;

    @Override
    public void sendEmailNotification(EmailCodeEvent event) {
        log.info("Sent event for email code notification: {}", event);
        kafkaTemplate.send(emailEventTopic, event);
    }

}