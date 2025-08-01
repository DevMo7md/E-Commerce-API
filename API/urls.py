from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
urlpatterns = [
    path('products/', views.Products.as_view(), name='products'),
    path('products/top/', views.TopProducts.as_view(), name='top_products'),
    path('products/<int:pk>/', views.ProductDetails.as_view(), name='products_details'),
    path('products/<int:product_id>/related-products/', views.RelatedProducts.as_view(), name='related_products'),
    path('reviews/', views.Reviews.as_view(), name='reveiws'),
    path('reviews/<int:pk>/', views.ReviewDetails.as_view(), name='review_details'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('categories/', views.CategoryList.as_view(), name='categories'),
    path('categories/<int:pk>/', views.CategoryDetails.as_view(), name='category'),
    path('cart/', views.CartList.as_view(), name='cart'),
    path('cart/<int:pk>/', views.CartItemDetails.as_view(), name='update_cart'),
    path('orders/', views.Orders.as_view(), name='orders'),
    path('orders/<int:pk>/', views.Order_datails.as_view(), name='order'),
    path('orders/<int:pk>/update-status/', views.OrderDeleviring.as_view(), name='order_status'),
    path('create-orders/', views.OrderCreate.as_view(), name='create_order'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]