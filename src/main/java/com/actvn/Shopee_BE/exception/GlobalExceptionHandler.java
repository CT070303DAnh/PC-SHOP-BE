package com.actvn.Shopee_BE.exception;

import com.actvn.Shopee_BE.dto.response.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.Objects;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Response> handleAllException(
            Exception exception, MethodArgumentNotValidException validException,
            WebRequest webRequest) {

        String errorMessage = Objects.requireNonNull(validException.getBindingResult()
                        .getFieldError())
                .getDefaultMessage();

        Response errorResponse = Response.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .message(validException.getBody().getDetail())
                .body(errorMessage)
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<Response> handleNotFoundException(NotFoundException exception) {
        Response errorResponse = Response.builder()
                .status(HttpStatus.NOT_FOUND)
                .message(exception.getMessage())
                .body(exception.getMessage())
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(errorResponse);
    }
}
