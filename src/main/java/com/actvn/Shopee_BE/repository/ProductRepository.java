package com.actvn.Shopee_BE.repository;

import com.actvn.Shopee_BE.entity.Category;
import com.actvn.Shopee_BE.entity.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProductRepository extends JpaRepository<Product, String> {
    List<Product> findByCategory(Category category);

    List<Product> findByCategoryOrderByPriceAsc(Category category);

    Page<Product> findByProductNameLikeIgnoreCase(String keyword, Pageable pageable);
}
