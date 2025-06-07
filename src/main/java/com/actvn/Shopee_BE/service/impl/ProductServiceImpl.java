package com.actvn.Shopee_BE.service.impl;

import com.actvn.Shopee_BE.common.Constants;
import com.actvn.Shopee_BE.dto.request.ProductRequest;
import com.actvn.Shopee_BE.dto.response.ProductItemResponse;
import com.actvn.Shopee_BE.dto.response.ProductResponse;
import com.actvn.Shopee_BE.dto.response.Response;
import com.actvn.Shopee_BE.entity.Category;
import com.actvn.Shopee_BE.entity.Product;
import com.actvn.Shopee_BE.exception.NotFoundException;
import com.actvn.Shopee_BE.repository.CategoryRepository;
import com.actvn.Shopee_BE.repository.ProductRepository;
import com.actvn.Shopee_BE.service.FileService;
import com.actvn.Shopee_BE.service.ProductService;
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

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductServiceImpl implements ProductService {
    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private FileService fileService;

    @Value("${project.image}")
    private String path;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public Response createNewProduct(String categoryId, ProductRequest productRequest) {
        Category category = findCategoryById(categoryId);
        // special_price = price - (discount * 0.01) * price
        double specialPrice = productRequest.getPrice() - (productRequest.getDiscount() * 0.01) * productRequest.getPrice();

        Product product = new Product();
        product.setProductName(productRequest.getProductName());
        product.setDescription(productRequest.getDescription());
        product.setDiscount(productRequest.getDiscount());
        product.setPrice(productRequest.getPrice());
        product.setQuantity(productRequest.getQuantity());
        product.setCategory(category);
        product.setSpecialPrice(specialPrice);
        product.setImage("default_image.png");
        product.setUpdateAt(LocalDateTime.now());

        Product created = productRepository.save(product);

        return Response.builder()
                .status(HttpStatus.CREATED)
                .message("Product created successfully!")
                .body(created)
                .build();
    }

    @Override
    public Response<Object> getAllProducts(int pageNumber, int pageSize, String sortBy, String sortOrder) {
        Sort sortByAndOrder = sortOrder.equals(Constants.CATEGORY_SORT_ORDER)
                ? Sort.by(sortBy).ascending()
                : Sort.by(sortBy).descending();

        Pageable pageable = PageRequest.of(pageNumber, pageSize, sortByAndOrder);
        Page<Product> productPage = productRepository.findAll(pageable);

        List<Product> products = productPage.getContent();

        List<ProductItemResponse> list = products.stream()
                .map(item -> modelMapper.map(item, ProductItemResponse.class))
                .collect(Collectors.toList());

        ProductResponse productResponse = new ProductResponse();
        productResponse.setContext(list);
        productResponse.setPageNumber(productPage.getNumber() + 1);
        productResponse.setPageSize(productPage.getSize());
        productResponse.setTotalElements(productPage.getTotalElements());
        productResponse.setTotalPages(productPage.getTotalPages());
        productResponse.setLastPage(productPage.isLast());
        productResponse.setFirstPage(productPage.isFirst());

        return Response.builder()
                .status(HttpStatus.OK)
                .body(productResponse)
                .message("Get all categories successfully!")
                .build();

    }

    @Override
    public Response<Object> getAProductById(String productId) {
        Product product =  findProductById(productId);
        ProductItemResponse productItemResponse = modelMapper.map(product, ProductItemResponse.class);
        return Response.builder()
                .status(HttpStatus.OK)
                .message("Get A product by Id successfully!")
                .body(productItemResponse)
                .build();
    }

    @Override
    public Response<Object> getAllProductsByCategory(String categoryId) {
        Category category = findCategoryById(categoryId);
        List<Product> products = productRepository.findByCategory(category);
        //List<Product> list = productRepository.findByCategoryOrderByPriceAsc(category);

        return Response.builder()
                .status(HttpStatus.CREATED)
                .message("Get all product by category successfully!")
                .body(products)
                .build();
    }

    @Override
    public Response<Object> getProductByKeyword(String keyword,
                                                int pageNumber, int pageSize,
                                                String sortBy, String sortOrder) {

        Sort sortByAndOrder = sortOrder.equals(Constants.PRODUCT_SORT_ORDER)
                ? Sort.by(sortBy).ascending()
                : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(pageNumber, pageSize, sortByAndOrder);

        Page<Product> productPage =
                productRepository.findByProductNameLikeIgnoreCase(
                        '%' + keyword + '%',
                        pageable);
        List<Product> products = productPage.getContent();
        /*List<ProductItemResponse> list = products.stream()
                .map(mapper::mapProductToDto)
                .toList();*/
        List<ProductItemResponse> list = products.stream()
                .map(item -> modelMapper.map(item, ProductItemResponse.class))
                .collect(Collectors.toList());

        ProductResponse productResponse = new ProductResponse();
        productResponse.setContext(list);
        productResponse.setPageNumber(productPage.getNumber() + 1);
        productResponse.setPageSize(productPage.getSize());
        productResponse.setTotalElements(productPage.getTotalElements());
        productResponse.setTotalPages(productPage.getTotalPages());
        productResponse.setLastPage(productPage.isLast());
        productResponse.setFirstPage(productPage.isFirst());

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Get all product by keyword successfully!")
                .body(productResponse)
                .build();
    }

    @Override
    public Response<Object> updateProductImage(String productId, MultipartFile image) {
        Product product = findProductById(productId);

        String fileName = fileService.uploadImage(path, image);
        product.setImage(fileName);

        Product savedProduct = productRepository.save(product);
        ProductItemResponse dto = modelMapper.map(savedProduct, ProductItemResponse.class);

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Update product image successfully!")
                .body(dto)
                .build();
    }

    @Override
    public Response updateProductById(String id, ProductRequest dtoRequest) {
        Product product = findProductById(id);
        product.setProductName(dtoRequest.getProductName());
        product.setDescription(dtoRequest.getDescription());
        product.setDiscount(dtoRequest.getDiscount());
        product.setPrice(dtoRequest.getPrice());
        product.setImage(dtoRequest.getImage());
        product.setQuantity(dtoRequest.getQuantity());
        double specialPrice = dtoRequest.getPrice() - (dtoRequest.getDiscount() * 0.01) * dtoRequest.getPrice();
        product.setSpecialPrice(specialPrice);
        productRepository.save(product);

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Update product with id: " + id + " successfully!")
                .build();
    }

    @Override
    public Response deleteProductById(String id) {
        Product product = findProductById(id);
        productRepository.delete(product);

        return Response.builder()
                .status(HttpStatus.OK)
                .message("Delete product with id: " + id + " successfully!")
                .build();
    }

    private Category findCategoryById(String id) {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Category with id:" + id + " not found!"));
        return category;
    }

    private Product findProductById(String productId) {
        Product foundProduct = productRepository.findById(productId)
                .orElseThrow(() -> new NotFoundException("Product with id:" + productId + " not found!"));
        return foundProduct;
    }
}
