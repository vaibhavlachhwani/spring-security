package com.vaibhav.springsecurity.controllers;

import com.vaibhav.springsecurity.entities.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api")
public class MessageController {

    private Logger logger = LoggerFactory.getLogger(getClass());

    public static final List<Message> MESSAGE_LIST = List.of(
            new Message(1, "vxbxv", LocalDateTime.now().plusMinutes(35565), "Message 1 : What The Commit"),
            new Message(2, "alice", LocalDateTime.now().plusMinutes(89445), "Here be Dragons"),
            new Message(3, "vxbxv", LocalDateTime.now().minusMinutes(669112), "I can't believe it took so long to fix this.")
    );

    @GetMapping("/messages")
    public List<Message> getAllMessages() {
        return MESSAGE_LIST;
    }

    @GetMapping("/users/{username}/messages")
    public List<Message> getAllMessagesForUser(@PathVariable String username) {
        return MESSAGE_LIST
                .stream()
                .filter(message -> message.getUser().equals(username))
                .toList();
    }

    @PostMapping("/users/{username}/messages")
    public void createMessageForUser(@PathVariable String username, @RequestBody Message message) {
        logger.info("Creating {} for {}", message, username);
    }
}
