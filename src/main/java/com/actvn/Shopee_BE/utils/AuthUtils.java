package com.actvn.Shopee_BE.utils;

import com.actvn.Shopee_BE.entity.User;
import com.actvn.Shopee_BE.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class AuthUtils {
  @Autowired
  private UserRepository userRepository;

  public String getEmailLogger(){
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    User user = userRepository.findByUserName(authentication.getName())
      .orElseThrow(() -> new UsernameNotFoundException(
        "User not found with username: " + authentication.getName()
      ));
    return user.getEmail();
  }

  public String getUserIdLogger(){
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    User user = userRepository.findByUserName(authentication.getName())
      .orElseThrow(() -> new UsernameNotFoundException(
        "User not found with username: " + authentication.getName()
      ));
    return user.getId();
  }

  public User getUserLogger(){
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    User user = userRepository.findByUserName(authentication.getName())
      .orElseThrow(() -> new UsernameNotFoundException(
        "User not found with username: " + authentication.getName()
      ));
    return user;
  }
}
