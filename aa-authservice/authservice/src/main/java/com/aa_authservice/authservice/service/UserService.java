package com.aa_authservice.authservice.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.aa_authservice.authservice.modal.User;
import com.aa_authservice.authservice.repository.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    // Method to check if the user exists by sid and sub
    public boolean checkUserExistsBySidAndSub(String sid, String sub) {
        return userRepository.existsBySessionIdAndId(sid, sub);
    }

    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }
}
