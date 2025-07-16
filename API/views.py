from django.shortcuts import render, get_object_or_404
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

class Products(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        products = Product.objects.all()
        paginator = PageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)
        serializer = ProductSerializer(paginated_products, many=True)
        return Response(serializer.data)
    

class Reviews(APIView):

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated()]
        return [AllowAny()]

    def get(self, request):
        reviews = Review.objects.all().order_by('-created_at')
        paginator = PageNumberPagination()
        pagenated_reveiws = paginator.paginate_queryset(reviews, request)
        serializer = ReviewSerializer(pagenated_reveiws, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ReviewSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Review created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ReveiwDetails(APIView):
    permission_classes = [IsAuthenticated]
    
    def put(self, request, pk):
        reviw = get_object_or_404(Review, pk=pk)
        serializer = ReviewSerializer(reviw, data=request.data, context={'request':request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        reveiw = get_object_or_404(Review, pk=pk)
        reveiw.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)