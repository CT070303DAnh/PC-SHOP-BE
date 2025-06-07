package com.actvn.Shopee_BE.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Response<T> {
    private final LocalDateTime timestamp = LocalDateTime.now();
    private HttpStatus status;
    private String message;

    private T body;
}
