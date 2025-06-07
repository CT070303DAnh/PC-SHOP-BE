package com.actvn.Shopee_BE.service.impl;

import com.actvn.Shopee_BE.dto.request.UserRequest;
import com.actvn.Shopee_BE.dto.response.Response;
import com.actvn.Shopee_BE.entity.User;
import com.actvn.Shopee_BE.repository.UserRepository;
import com.actvn.Shopee_BE.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    public UserRepository userRepository;

    @Override
    public boolean existByUserName(String userName) {
        return userRepository.existsByUserName(userName);
    }

    @Override
    public boolean existByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public Response createNewUser(UserRequest newUser) {
        User user = new User(newUser.getUserName(), newUser.getEmail(), newUser.getPassword());
        user.setRoles(newUser.getRoles());
       User created = userRepository.save(user);

        return Response.builder()
                .status(HttpStatus.CREATED)
                .message("User created successfully!")
                .body(created)
                .build();
    }
}
