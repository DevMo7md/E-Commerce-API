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
    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [AllowAny()]

    def get(self, request):
        products = Product.objects.all()
        paginator = PageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)
        serializer = ProductSerializer(paginated_products, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = ProductSerializer(data=request.data, context={'request':request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'Product is created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    

class ProductDetails(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]
    
    def get(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        serializer = ProductSerializer(product, many=False)
        return Response(serializer.data , status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        serializer = ProductSerializer(product, data=request.data, context={'request':request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'product updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        product.delete()
        return Response({'message':'Product deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

class RelatedProducts(APIView):
    permission_classes = [AllowAny]

    def get(self, request, product_id):
        product = get_object_or_404(Product, pk=product_id)
        category = product.category
        related_products = Product.objects.filter(category=category).exclude(id=product.id).order_by('-num_of_sales')[:10]
        serializer = ProductSerializer(related_products, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK )
    

class TopProducts(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        top_products = Product.objects.order_by('-num_of_sales')[:10]
        serializer = ProductSerializer(top_products, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK )


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
    
class ReviewDetails(APIView):
    permission_classes = [IsAuthenticated]
    
    def put(self, request, pk):
        review = get_object_or_404(Review, pk=pk)
        if request.user != review.user:
            return Response({'message':'You are not allowed to edit'}, status=status.HTTP_403_FORBIDDEN)
    
        serializer = ReviewSerializer(review, data=request.data, context={'request':request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'review updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    
    def delete(self, request, pk):
        review = get_object_or_404(Review, pk=pk)
        if request.user != review.user:
            return Response({'message':'You are not allowed to edit'}, status=status.HTTP_403_FORBIDDEN)
        
        review.delete()
        return Response({'message':'review deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    

class CategoryList(APIView):
    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [AllowAny()]

    def get(self, request):
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'category created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CategoryDetails(APIView):
    permission_classes = [IsAdminUser]
    
    def put(self, request, pk):
        category = get_object_or_404(Category, pk=pk)
        serializer = CategorySerializer(category, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'category updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        category = get_object_or_404(Category, pk=pk)
        category.delete()
        return Response({'message':'category deleted successfully'},status=status.HTTP_204_NO_CONTENT)
    

class CartList(APIView):

    permission_classes = [IsAuthenticated]  

    def get(self, request):
        user = self.request.user
        cart, created = Cart.objects.get_or_create(user=user)
        serializer = CartSerializer(cart, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        user = self.request.user
        product_id = request.data.get('product_id')
        quantity = int(request.data.get('quantity', 1))

        product = get_object_or_404(Product, id=product_id)
        cart, created = Cart.objects.get_or_create(user=user)

        cart_item, cart_item_created = CartItem.objects.get_or_create(cart=cart, product=product, defaults={'quantity':quantity})

        if not cart_item_created:
            cart_item.quantity += quantity

        cart_item.save()
        return Response({'message': 'cart updated successfully'}, status= status.HTTP_200_OK)


class CartItemDetails(APIView):

    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        cart_item = get_object_or_404(CartItem, pk=pk)
        serializer = CartItemSerializer(cart_item ,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'cart item updated'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        cart_item = get_object_or_404(CartItem, pk=pk)
        cart_item.delete()
        return Response({'message':'Item deleted'}, status=status.HTTP_204_NO_CONTENT)
    

class Orders(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_staff:
            orders = Order.objects.all().order_by('date_of_order')
        else :
            orders = Order.objects.filter(user=request.user).order_by('date_of_order')
        pagenator = PageNumberPagination()
        pagenated_orders = pagenator.paginate_queryset(orders, request)
        serializer = OrderSerializer(pagenated_orders, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class Order_datails(APIView):

    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        order = get_object_or_404(Order, pk=pk)
        if self.request.user == order.user:
            serializer = OrderSerializer(order, many=False)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'messaage':'This page is not allowed for you'}, status=status.HTTP_400_BAD_REQUEST)


class OrderCreate(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = OrderSerializer(data=request.data, context={'request':request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Order is created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class OrderDeleviring(APIView):
    permission_classes = [IsAdminUser]

    def put(self, request, pk):
        order = get_object_or_404(Order, pk=pk)
        cart, _ = Cart.objects.get_or_create(user=order.user)
        serializer = OrderDeleviringSerializer(order, data=request.data)
        if serializer.is_valid():
            serializer.save()
            order.refresh_from_db()

            if order.payment_status == 'PAID':
                cart.products.clear()
            def update_product_sales(order_items, add=True):
                for item in order_items:
                    if add:
                        item.product.num_of_sales += item.quantity
                    else:
                        item.product.num_of_sales = max(0, item.product.num_of_sales - item.quantity)
                    item.product.save()

            if order.status == 'DELIVERED' and order.payment_status == 'PAID' :
                update_product_sales(order.order_items.all(), add=True)
                
            elif order.status == 'RETRIEVED' and order.payment_status == 'REFUNDED' :
                update_product_sales(order.order_items.all(), add=False)
                
                    
            return Response({'message':'Order status updated'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


