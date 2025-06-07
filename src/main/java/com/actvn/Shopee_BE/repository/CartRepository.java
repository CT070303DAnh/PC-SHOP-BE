package com.actvn.Shopee_BE.repository;

import com.actvn.Shopee_BE.entity.Cart;
import com.actvn.Shopee_BE.entity.CartItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface CartRepository extends JpaRepository<Cart, String> {
  @Query(
    value = "select c from Cart c where c.user.email = ?1"
  )
  Cart findCartByEmail(String email);

  @Query(
          value = "select c from Cart c where c.user.email = ?1 and c.cartId=?2"
  )
  Cart findCartByEmailAndCartId(String email, String cartId);
}
