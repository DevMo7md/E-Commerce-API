from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
urlpatterns = [
    path('products/', views.Products.as_view(), name='products'),
    path('products/<int:pk>/', views.ProductDetails.as_view(), name='products_details'),
    path('reviews/', views.Reviews.as_view(), name='reveiws'),
    path('reviews/<int:pk>/', views.ReviewDetails.as_view(), name='review_details'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('categories/', views.CategoryList.as_view(), name='categories'),
    path('categories/<int:pk>/', views.CategoryDetails.as_view(), name='category'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]