from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status, generics
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import JSONParser
from rest_framework.pagination import PageNumberPagination
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser, IsAuthenticatedOrReadOnly
from rest_framework.decorators import permission_classes
from .models import *
from .serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
# Create your views here.

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class products(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        products = Product.objects.all()
        paginator = PageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)
        serializer = ProductSerializer(paginated_products, many=True)
        return Response(serializer.data)
    

