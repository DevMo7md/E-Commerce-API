from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
urlpatterns = [
    path('products/', views.Products.as_view(), name='products'),
    path('reveiws/', views.Reviews.as_view(), name='reveiws'),
    path('reveiws/<int:pk>/', views.ReveiwDetails.as_view(), name='reveiw_details'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]