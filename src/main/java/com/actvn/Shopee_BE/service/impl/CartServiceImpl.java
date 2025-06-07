package com.actvn.Shopee_BE.service.impl;

import com.actvn.Shopee_BE.dto.response.CartResponse;
import com.actvn.Shopee_BE.dto.response.ProductItemResponse;
import com.actvn.Shopee_BE.dto.response.Response;
import com.actvn.Shopee_BE.entity.Cart;
import com.actvn.Shopee_BE.entity.CartItem;
import com.actvn.Shopee_BE.entity.Product;
import com.actvn.Shopee_BE.exception.ApiException;
import com.actvn.Shopee_BE.exception.NotFoundException;
import com.actvn.Shopee_BE.repository.CartItemRepository;
import com.actvn.Shopee_BE.repository.CartRepository;
import com.actvn.Shopee_BE.repository.ProductRepository;
import com.actvn.Shopee_BE.service.CartService;
import com.actvn.Shopee_BE.utils.AuthUtils;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Service
public class CartServiceImpl implements CartService {

    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private CartItemRepository cartItemRepository;

    @Autowired
    private AuthUtils authUtils;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public Response addProductToCart(String productId, int quantity) {
        Cart cart = createCart();
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new NotFoundException("Not found product"));
        CartItem cartItem = cartItemRepository.findCartItemByProductIdAndCartId(cart.getCartId(), productId);
        System.out.println(cartItem);
        if (cartItem != null) {
            throw new ApiException("Product with product name: " + product.getProductName() + "already exists in the cart");
        }
        if (product.getQuantity() == 0) {
            throw new ApiException("Product name: " + product.getProductName() + "is not available");
        }
        if (quantity > product.getQuantity()) {
            throw new ApiException("Số lượng vượt quá số lượng sản phẩm có, cần ít hơn" + product.getQuantity());
        }
        CartItem newCartItem = new CartItem();
        newCartItem.setProduct(product);
        newCartItem.setCart(cart);
        newCartItem.setQuantity(quantity);
        newCartItem.setDiscount(product.getDiscount());
        newCartItem.setProductPrice(product.getSpecialPrice());

        cartItemRepository.save(newCartItem);

//        product.setQuantity(quantity);
        cart.setTotalPrice(cart.getTotalPrice() + (product.getSpecialPrice() * quantity));
        synchronized (this) {
            cartRepository.save(cart);
        }

        CartResponse cartResponse = modelMapper.map(cart, CartResponse.class);
        List<CartItem> cartItems = cart.getCartItems();
        Stream<ProductItemResponse> productItemResponseStream = cartItems.stream().map(item -> {
            ProductItemResponse map = modelMapper.map(item.getProduct(), ProductItemResponse.class);
            map.setQuantity(quantity);
            return map;
        });
        cartResponse.setProducts(productItemResponseStream.toList());

        return Response.builder()
                .status(HttpStatus.OK)
                .body(cartResponse)
                .message("Cart đã được tạo")
                .build();
    }

    @Override
    public Response updateProductQuantityInCarts(String productId, int quantity) {
        String email = authUtils.getEmailLogger();
        System.out.println(email);
        Cart userCart = cartRepository.findCartByEmail(email);
        String cartId = userCart.getCartId();
        System.out.println(cartId);
        Cart cart = cartRepository.findById(cartId)
                .orElseThrow(() -> new ApiException("Lấy cart không thành công"));

        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ApiException("Không tìm thấy sản phẩm"));
        if (product.getQuantity() == 0) {
            throw new ApiException(("Không con san phẩm trong kho"));
        }
        if (product.getQuantity() < quantity) {
            throw new ApiException("Cần lấy sản phẩm bé hơn sản phẩm trong kho");
        }

        CartItem cartItem = cartItemRepository.findCartItemByProductIdAndCartId(cartId, productId);

        if (cartItem == null) {
            throw new ApiException("Sản phẩm không được tìm thấy");
        }

        int newQuantity =  cartItem.getQuantity() + quantity;
        if (newQuantity < 0) {
            throw new ApiException("SỐ lượng sản phảm không đúng");
        }

        if (newQuantity == 0) {
            deleteProductFromCart(cartId, productId);
        } else {
            cartItem.setProductPrice(product.getSpecialPrice());
            cartItem.setQuantity(newQuantity);
            cartItem.setDiscount(cartItem.getDiscount());
            cart.setTotalPrice(cart.getTotalPrice() + (cartItem.getProductPrice()) * quantity);
            cartRepository.save(cart);
        }

        CartItem updateItem = cartItemRepository.save(cartItem);
        if(updateItem.getQuantity() == 0){
            cartRepository.deleteById(updateItem.getCartItemId());
        }
        CartResponse cartDTO = modelMapper.map(cart, CartResponse.class);
        List<CartItem> cartItems = cart.getCartItems();
        List<ProductItemResponse> productItemDTOs =  cartItems.stream().map(
                item -> {
                    ProductItemResponse dto = modelMapper.map(item.getProduct(), ProductItemResponse.class);
                    dto.setQuantity(newQuantity);
                    return dto;
                }
        ).toList();

        cartDTO.setProducts(productItemDTOs);
        return Response.builder()
                .status(HttpStatus.OK)
                .body(cartDTO)
                .message("Cart Updated completed")
                .build();
    }

    @Override
    public void updateProductInCarts(String cartId, String productId) {

    }

    @Override
    public Response deleteProductFromCart(String cartId, String productId) {
        Cart cart = cartRepository.findById(cartId)
                .orElseThrow(() -> new NotFoundException("Can't not found"));
        CartItem cartItem = cartItemRepository.findCartItemByProductIdAndCartId(cartId, productId);
        log.info("CartItem to delete: {}", cartItem);
        if (cartItem == null) {
            throw new ApiException("Can't not found product");
        }
        cart.setTotalPrice(cart.getTotalPrice() - (cartItem.getProductPrice() * cartItem.getQuantity()));

        cartItemRepository.deleteCartItemByProductIdAndCartId(cartId, productId);
        cartRepository.save(cart);
        return Response.builder()
                .status(HttpStatus.OK)
                .body(true)
                .message("product delete successfully")
                .build();
    }

    @Override
    public Response getCartById() {
        String email = authUtils.getEmailLogger();
        Cart cart = cartRepository.findCartByEmail(email);
        String cartId = cart.getCartId();

        return Response.builder()
                .status(HttpStatus.OK)
                .body(getCart(email, cartId))
                .message("Lấy cart có id là " + cartId + "thành công")
                .build();

    }

    private CartResponse getCart(String email, String cartId) {
        Cart cart = cartRepository.findCartByEmailAndCartId(email, cartId);
        if (cart == null) {
            throw new ApiException("Cart" + cartId + "not found");
        }
        CartResponse cartDTO = modelMapper.map(cart, CartResponse.class);
        List<ProductItemResponse> productDTOs = cart.getCartItems().stream()
                .map(cartItem -> {
                  ProductItemResponse map =  modelMapper.map(cartItem.getProduct(), ProductItemResponse.class);
                  map.setQuantity(cartItem.getQuantity());
                  return map;
                })
                .toList();
        cartDTO.setProducts(productDTOs);
        return cartDTO;
    }

    @Override
    public Response<Object> getAllCarts() {
        List<Cart> carts = cartRepository.findAll();
        if (carts.size() == 0) {
            throw new ApiException("No carts exists");
        }
        // Chuyển đổi danh sách Cart sang danh sách CartResponse
        List<CartResponse> cartDTOs = carts.stream().map(cart -> {
            // Chuyển đổi Cart sang CartResponse
            CartResponse cartDTO = modelMapper.map(cart, CartResponse.class);

            // Chuyển đổi danh sách ProductItem trong Cart sang danh sách ProductItemResponse
            List<ProductItemResponse> productDTOs = cart.getCartItems().stream()
                    .map(cartItem -> {
                       ProductItemResponse map = modelMapper.map(cartItem.getProduct(), ProductItemResponse.class);
                               map.setQuantity(cartItem.getQuantity());
                       return map;
                    })
                    .collect(Collectors.toList());

            // Gán danh sách sản phẩm vào CartResponse
            cartDTO.setProducts(productDTOs);

            return cartDTO; // Trả về CartResponse
        }).collect(Collectors.toList());
        return Response.builder()
                .status(HttpStatus.OK)
                .body(cartDTOs)
                .message("List Cart đã duọc liệt ra")
                .build();

    }

    private Cart createCart() {
        Cart userCart = cartRepository.findCartByEmail(authUtils.getEmailLogger());
        if (userCart != null) {
            return userCart;
        }

        Cart cart = new Cart();
        cart.setTotalPrice(0.00);
        cart.setUser(authUtils.getUserLogger());

        Cart savedCart = cartRepository.save(cart);
        return savedCart;
    }
}
