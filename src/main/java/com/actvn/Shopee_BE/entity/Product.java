package com.actvn.Shopee_BE.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@Entity
@Table(name = "products")
public class Product {
  @Column(name = "create_at")
  private final LocalDateTime createAt = LocalDateTime.now();
  @Column(name = "update_at")
  private LocalDateTime updateAt = LocalDateTime.now();
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private String id;

  @Column(name = "product_name")
  private String productName;

  private String description;
  private double discount;
  private double price;
  private String image;
  private int quantity;

  @Column(name = "special_price")
  private double specialPrice;

  @ManyToOne
  @JoinColumn(name = "category_id")
  private Category category;

  @ManyToOne
  @JoinColumn(name = "seller_id")
  private User user;

  @OneToMany(mappedBy = "product", cascade = {CascadeType.PERSIST, CascadeType.MERGE}, fetch = FetchType.EAGER)
  private List<CartItem> products = new ArrayList<>();
}
