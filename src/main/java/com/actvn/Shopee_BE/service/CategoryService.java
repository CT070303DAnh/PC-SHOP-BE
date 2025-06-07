package com.actvn.Shopee_BE.service;

import com.actvn.Shopee_BE.dto.request.CategoryRequest;
import com.actvn.Shopee_BE.dto.response.Response;
import org.springframework.web.multipart.MultipartFile;

public interface CategoryService {
    Response getAllCategories(int pageNumber, int pageSize, String sortBy, String sortOrder);

    Response getAllCategoriesNoPage();

    Response createNewCategory(CategoryRequest categoryRequest);

    Response getCategoryById(String id);

    Response updateCategoryById(String id, CategoryRequest dtoRequest);

    Response deleteCategoryById(String id);

    Response<Object> updateCategoryImage(String id, MultipartFile image);
}
