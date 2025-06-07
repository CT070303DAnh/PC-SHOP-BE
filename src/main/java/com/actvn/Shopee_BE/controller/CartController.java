package com.actvn.Shopee_BE.controller;

import com.actvn.Shopee_BE.dto.response.Response;
import com.actvn.Shopee_BE.service.CartService;
import com.actvn.Shopee_BE.utils.AuthUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin("http://localhost:3000/cart")
@RequestMapping("/api/carts")
public class CartController {

    @Autowired
    private CartService cartService;

    @Autowired
    private AuthUtils authUtils;

    @PostMapping("/products/{productId}/quantity/{quantity}")
    public ResponseEntity<Response> addProductToCart(@PathVariable String productId,
                                                     @PathVariable int quantity
    ) {

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(cartService.addProductToCart(productId, quantity));
    }

    @PutMapping("/products/{productId}/quantity/{quantity}")
    public ResponseEntity<Response> updateCartProduct(@PathVariable String productId,
                                                              @PathVariable int quantity
    ) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(cartService.updateProductQuantityInCarts(productId, quantity));

    }

    @DeleteMapping("/{cartId}/product/{productId}")
    public ResponseEntity<Response> deleteProductFromCart(@PathVariable String cartId,
                                                                  @PathVariable String productId
    ) {
        System.out.println(productId);
        return ResponseEntity.status(HttpStatus.OK)
                .body(cartService.deleteProductFromCart(cartId,productId));
    }
    @CrossOrigin(origins = "http://localhost:3000/")
    @GetMapping("/users/cart")
    public ResponseEntity<Response> getCartById() {

        return ResponseEntity.status(HttpStatus.OK)
                .body(cartService.getCartById());


    }

    @GetMapping("")
    public ResponseEntity<Response> getCarts() {
        return ResponseEntity.status(HttpStatus.OK)
                .body(cartService.getAllCarts());
    }
}
