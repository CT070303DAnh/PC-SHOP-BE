package com.actvn.Shopee_BE.controller;

import com.actvn.Shopee_BE.common.Constants;
import com.actvn.Shopee_BE.dto.request.CategoryRequest;
import com.actvn.Shopee_BE.dto.request.ProductRequest;
import com.actvn.Shopee_BE.dto.response.Response;
import com.actvn.Shopee_BE.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController()
@CrossOrigin("http://localhost:3000/")
@RequestMapping("/api")
public class ProductController {
    @Autowired
    private ProductService productService;

    @PostMapping("/admin/categories/{categoryId}/product")
    public ResponseEntity<Response> createNewProduct(@PathVariable String categoryId, @RequestBody ProductRequest productRequest) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(productService.createNewProduct(categoryId, productRequest));
    }

    @GetMapping("/public/products/{productId}")
    public ResponseEntity<Response<Object>> getProductById(
            @PathVariable String productId
    ) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(productService.getAProductById(productId));

    }

    @GetMapping("/public/products")
    public ResponseEntity<Response<Object>> getAllProducts(
            @RequestParam(name = "pageNumber", defaultValue = Constants.PAGE_NUMBER, required = false) int pageNumber,
            @RequestParam(name = "pageSize", defaultValue = Constants.PAGE_SIZE, required = false) int pageSize,
            @RequestParam(name = "sortBy", defaultValue = Constants.PRODUCT_SORT_BY, required = false) String sortBy,
            @RequestParam(name = "sortOrder", defaultValue = Constants.PRODUCT_SORT_ORDER, required = false) String sortOrder
    ) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(productService.getAllProducts(pageNumber, pageSize, sortBy, sortOrder));
    }

    @GetMapping("/public/categories/{categoryId}/product")
    public ResponseEntity<Response> getAllProductsByCategory(
            @PathVariable String categoryId) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(productService.getAllProductsByCategory(categoryId));
    }

    @GetMapping("/public/products/keyword/{keyword}")
    public ResponseEntity<Response> getProductByKeyword(
            @PathVariable String keyword,
            @RequestParam(name = "pageNumber", defaultValue = Constants.PAGE_NUMBER, required = false) int pageNumber,
            @RequestParam(name = "pageSize", defaultValue = Constants.PAGE_SIZE, required = false) int pageSize,
            @RequestParam(name = "sortBy", defaultValue = Constants.PRODUCT_SORT_BY, required = false) String sortBy,
            @RequestParam(name = "sortOrder", defaultValue = Constants.PRODUCT_SORT_ORDER, required = false) String sortOrder
    ) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(productService.getProductByKeyword(keyword, pageNumber, pageSize, sortBy, sortOrder));
    }

    @PutMapping("/admin/products/{productId}/image")
    public ResponseEntity<Response> updateProductImage(
            @PathVariable String productId, @RequestParam("image") MultipartFile image) {

        return ResponseEntity.status(HttpStatus.OK)
                .body(productService.updateProductImage(productId, image));
    }
    @PutMapping("/admin/products/{id}")
    public ResponseEntity<Response> updateProductById(@PathVariable String id, @RequestBody ProductRequest dtoRequest) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(productService.updateProductById(id, dtoRequest));
    }
    @DeleteMapping("/admin/product/{id}")
    public ResponseEntity<Response> deleteProductById(@PathVariable String id) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(productService.deleteProductById(id));
    }
}
