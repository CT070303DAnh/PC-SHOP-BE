package com.actvn.Shopee_BE.controller;

import com.actvn.Shopee_BE.common.Constants;
import com.actvn.Shopee_BE.dto.request.CategoryRequest;
import com.actvn.Shopee_BE.dto.response.Response;
import com.actvn.Shopee_BE.service.CategoryService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController()
@CrossOrigin("http://localhost:3000/")
@RequestMapping("/api")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/public/categories")
    public ResponseEntity<Response> getCategories(
            @RequestParam(name = "pageNumber", defaultValue = Constants.PAGE_NUMBER, required = false) int pageNumber,
            @RequestParam(name = "pageSize", defaultValue = Constants.PAGE_SIZE, required = false) int pageSize,
            @RequestParam(name = "sortBy", defaultValue = Constants.CATEGORY_SORT_BY, required = false) String sortBy,
            @RequestParam(name = "sortOrder", defaultValue = Constants.CATEGORY_SORT_ORDER, required = false) String sortOrder
    ) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(categoryService.getAllCategories(pageNumber, pageSize, sortBy, sortOrder));
    }
    @GetMapping("/public/categories/all")
    public ResponseEntity<Response> getAllCategories(

    ) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(categoryService.getAllCategoriesNoPage());
    }

    @PostMapping("/admin/categories")
    public ResponseEntity<Response> createNewCategory(@Valid @RequestBody CategoryRequest categoryRequest) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(categoryService.createNewCategory(categoryRequest));
    }

    @GetMapping("/public/categories/{id}")
    public ResponseEntity<Response> getCategoryById(@PathVariable String id) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(categoryService.getCategoryById(id));
    }

    @PutMapping("/admin/categories/{id}")
    public ResponseEntity<Response> updateCategoryById(@PathVariable String id, @RequestBody CategoryRequest dtoRequest) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(categoryService.updateCategoryById(id, dtoRequest));
    }

    @DeleteMapping("/admin/categories/{id}")
    public ResponseEntity<Response> deleteCategoryById(@PathVariable String id) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(categoryService.deleteCategoryById(id));
    }

    @PutMapping("/admin/categories/{id}/image")
    public ResponseEntity<Response> updateCategoryImage(
            @PathVariable String id, @RequestParam("image") MultipartFile image) {

        return ResponseEntity.status(HttpStatus.OK)
                .body(categoryService.updateCategoryImage(id, image));
    }
}
