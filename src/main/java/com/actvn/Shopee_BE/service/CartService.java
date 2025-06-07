package com.actvn.Shopee_BE.service;

import com.actvn.Shopee_BE.dto.response.Response;

public interface CartService {
  Response<Object> addProductToCart(String productId, int quantity);

  Response<Object> updateProductQuantityInCarts(String productId, int quantity);

  void updateProductInCarts(String cartId, String productId);

  Response<Object> deleteProductFromCart(String cartId, String productId);

  Response<Object> getCartById();

 Response<Object> getAllCarts();
}
