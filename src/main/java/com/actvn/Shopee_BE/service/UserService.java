package com.actvn.Shopee_BE.service;

import com.actvn.Shopee_BE.dto.request.UserRequest;
import com.actvn.Shopee_BE.dto.response.Response;

public interface UserService {
    boolean existByUserName(String userName);

    boolean existByEmail(String email);

    Response<Object> createNewUser(UserRequest newUser);
}
