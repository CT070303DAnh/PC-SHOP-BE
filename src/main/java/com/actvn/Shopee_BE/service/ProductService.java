package com.actvn.Shopee_BE.service;

import com.actvn.Shopee_BE.dto.request.CategoryRequest;
import com.actvn.Shopee_BE.dto.request.ProductRequest;
import com.actvn.Shopee_BE.dto.response.ProductResponse;
import com.actvn.Shopee_BE.dto.response.Response;
import org.springframework.web.multipart.MultipartFile;

public interface ProductService {
    Response<Object> createNewProduct(String categoryId, ProductRequest productRequest);

    Response<Object> getAllProducts(int pageNumber, int pageSize, String sortBy, String sortOrder);

    Response<Object> getAProductById(String productId);

    Response<Object> getAllProductsByCategory(String categoryId);

    Response<Object> getProductByKeyword(String keyword,
                                         int pageNumber,
                                         int pageSize,
                                         String sortBy,
                                         String sortOrder);

    Response<Object> updateProductImage(String productId, MultipartFile image);

    Response updateProductById(String id, ProductRequest dtoRequest);

    Response deleteProductById(String id);
}
