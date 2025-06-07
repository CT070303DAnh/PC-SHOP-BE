package com.actvn.Shopee_BE.service.impl;

import com.actvn.Shopee_BE.common.Constants;
import com.actvn.Shopee_BE.dto.request.CategoryRequest;
import com.actvn.Shopee_BE.dto.response.CategoryItemResponse;
import com.actvn.Shopee_BE.dto.response.CategoryResponse;
import com.actvn.Shopee_BE.dto.response.ProductItemResponse;
import com.actvn.Shopee_BE.dto.response.Response;
import com.actvn.Shopee_BE.entity.Category;
import com.actvn.Shopee_BE.entity.Product;
import com.actvn.Shopee_BE.exception.NotFoundException;
import com.actvn.Shopee_BE.repository.CategoryRepository;
import com.actvn.Shopee_BE.service.CategoryService;
import com.actvn.Shopee_BE.service.FileService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CategoryServiceImpl implements CategoryService {

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private ModelMapper modelMapper;

    @Autowired
    private FileService fileService;

    @Value("${project.image}")
    private String path;

    @Override
    public Response getAllCategories(int pageNumber, int pageSize,
                                     String sortBy, String sortOrder) {

        Sort sortByAndOrder = sortOrder.equals(Constants.CATEGORY_SORT_ORDER)
                ? Sort.by(sortBy).ascending()
                : Sort.by(sortBy).descending();

        Pageable pageable = PageRequest.of(pageNumber, pageSize, sortByAndOrder);
        Page<Category> categoryPage = categoryRepository.findAll(pageable);

        List<Category> categories = categoryPage.getContent();

        List<CategoryItemResponse> list = categories.stream()
                .map(item -> modelMapper.map(item, CategoryItemResponse.class))
                .collect(Collectors.toList());

        CategoryResponse categoryResponse = new CategoryResponse();
        categoryResponse.setContext(list);
        categoryResponse.setPageNumber(categoryPage.getNumber() + 1);
        categoryResponse.setPageSize(categoryPage.getSize());
        categoryResponse.setTotalElements(categoryPage.getTotalElements());
        categoryResponse.setTotalPages(categoryPage.getTotalPages());
        categoryResponse.setLastPage(categoryPage.isLast());
        categoryResponse.setFirstPage(categoryPage.isFirst());

        return Response.builder()
                .status(HttpStatus.OK)
                .body(categoryResponse)
                .message("Get all categories successfully!")
                .build();
    }

    @Override
    public Response getAllCategoriesNoPage() {
        List<Category> categoryList = categoryRepository.findAll();
        List<CategoryItemResponse> list = categoryList.stream()
                .map(item -> modelMapper.map(item, CategoryItemResponse.class))
                .collect(Collectors.toList());
        return Response.builder()
                .status(HttpStatus.OK)
                .body(list)
                .message("Get all categories successfully!")
                .build();
    }

    @Override
    public Response createNewCategory(CategoryRequest categoryRequest) {
        Category category = new Category();
        category.setName(categoryRequest.getName());
        Category created = categoryRepository.save(category);

        return Response.builder()
                .status(HttpStatus.CREATED)
                .message("Category created successfully!")
                .body(created)
                .build();
    }

    @Override
    public Response getCategoryById(String id) {
        Category category = findCategoryById(id);
        CategoryItemResponse categoryDto = modelMapper.map(category, CategoryItemResponse.class);

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Get category with id: " + id + " successfully!")
                .body(categoryDto)
                .build();
    }

    @Override
    public Response updateCategoryById(String id, CategoryRequest dtoRequest) {
        Category category = findCategoryById(id);
        category.setName(dtoRequest.getName());
        categoryRepository.save(category);

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Update category with id: " + id + " successfully!")
                .build();
    }

    @Override
    public Response deleteCategoryById(String id) {
        Category category = findCategoryById(id);
        categoryRepository.delete(category);

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Delete category with id: " + id + " successfully!")
                .build();
    }

    @Override
    public Response<Object> updateCategoryImage(String id, MultipartFile image) {
        Category category = findCategoryById(id);

        String fileName = fileService.uploadImage(path, image);
        category.setImage(fileName);

        Category savedCategory = categoryRepository.save(category);
        CategoryItemResponse dto = modelMapper.map(savedCategory, CategoryItemResponse.class);

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Update category image successfully!")
                .body(dto)
                .build();
    }

    private Category findCategoryById(String id) {
        Category category = categoryRepository.findById(id).orElseThrow(() ->
                new NotFoundException("Category with id:" + id + " not found!"));
        return category;
    }
}
