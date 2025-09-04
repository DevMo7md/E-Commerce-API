from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status, generics
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.parsers import JSONParser
from rest_framework.pagination import PageNumberPagination
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser, IsAuthenticatedOrReadOnly, BasePermission
from rest_framework.decorators import permission_classes
from .models import *
from .serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache
from django.utils.crypto import get_random_string
from django.urls import reverse
from django.db.models import Q
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

import logging

logger = logging.getLogger(__name__)

# Email verification imports
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model

class IsDeliveryOrSuperUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (request.user.is_superuser or request.user.is_delivery)
class IsSellerOrSuperUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (request.user.is_superuser or request.user.is_seller)


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    data = cache.get(f"register_{token}")
    if not data:
        # Temporary url until frontend is ready
        return redirect('https://yourfrontend.com/email-verification?status=error&reason=expired')
    # Create user
    serializer = RegisterSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        cache.delete(f"register_{token}")
        # Temporary url until frontend is ready
        return redirect('https://yourfrontend.com/email-verification?status=success')
    # Temporary url until frontend is ready
    return redirect('https://yourfrontend.com/email-verification?status=error&reason=invalid_data')


class RegisterView(APIView):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            User = get_user_model()
            if User.objects.filter(email=serializer.validated_data['email']).exists():
                return Response({'error': 'البريد الإلكتروني مستخدم بالفعل.'}, status=400)
            
            token = get_random_string(32)
            # Store registration data in cache for 10 min
            cache.set(f"register_{token}", serializer.validated_data, timeout=600)

            verification_link = request.build_absolute_uri(
                reverse('email-verify', kwargs={'token': token})
            )

            subject = 'Verify your email'
            html_message = render_to_string('email/email_verification.html', {'verification_link': verification_link})
            plain_message = strip_tags(html_message)
            send_mail(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [serializer.validated_data['email']], html_message=html_message)
            return Response({'message': 'Please check your email to verify your account.'}, status=201)
        return Response(serializer.errors, status=400)

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

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        id_token_str = request.data.get('id_token')
        if not id_token_str:
            return Response({'error': 'id_token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # تحقق من الـ token عند Google
            idinfo = id_token.verify_oauth2_token(id_token_str, google_requests.Request())

            email = idinfo.get('email')
            if not email:
                return Response({'error': 'Email not found in token.'}, status=status.HTTP_400_BAD_REQUEST)

            User = get_user_model()
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email,
                    'first_name': idinfo.get('given_name', ''),
                    'last_name': idinfo.get('family_name', ''),
                    'is_seller': False,
                    'is_delivery': False,
                    'phone_number': idinfo.get('phone_number', ''),
                    'address': idinfo.get('address', '')
                    }  
            )

            # اصدار JWT
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'is_new_user': created 
            })

        except ValueError as e:
            logger.error(f"Google token verification failed: {str(e)}")
            return Response({'error': 'Invalid token', 'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request(request):
    email = request.data.get('email')
    User = get_user_model()
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'message': 'If this email exists, a reset link has been sent.'}, status=200)
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    frontend_base_url = 'https://localhost:3000/reset-password' # Temporary URL until frontend is ready
    reset_link = f'{frontend_base_url}/{uid}/{token}/'
    subject = 'Reset Your Password'
    html_message = render_to_string('email/password_reset.html', {'reset_link': reset_link, 'user': user})
    plain_message = strip_tags(html_message)
    send_mail(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [user.email], html_message=html_message)
    return Response({'message': 'If this email exists, a reset link has been sent.'}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm(request, uidb64, token):
    User = get_user_model()
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'message': 'Invalid link.'}, status=400)
    if not default_token_generator.check_token(user, token):
        return Response({'message': 'Invalid or expired token.'}, status=400)
    password = request.data.get('password')
    if not password:
        return Response({'message': 'Password is required.'}, status=400)
    user.set_password(password)
    user.save()
    return Response({'message': 'Password has been reset successfully.'}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def email_reset_request(request):
    new_email = request.data.get('new_email')
    user = request.user
    if not new_email:
        return Response({'message': 'New email is required.'}, status=400)
    
    User = get_user_model()
    if User.objects.filter(email=new_email).exists():
        return Response({'message': 'This email is already in use.'}, status=400)
    
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    frontend_base_url = 'https://localhost:3000/confirm-email-change' # Temporary URL until frontend is ready
    confirm_link = f'{frontend_base_url}/{uid}/{token}/?new_email={new_email}'
    subject = 'Update Your Email'
    html_message = render_to_string('email/email_update.html', {'confirm_link': confirm_link, 'user': user})
    plain_message = strip_tags(html_message)
    send_mail(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [new_email], html_message=html_message)
    return Response({'message': 'If this email exists, the update link has been sent.'}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def email_reset_confirm(request, uidb64, token):
    User = get_user_model()
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'message': 'Invalid link.'}, status=400)
    if not default_token_generator.check_token(user, token):
        return Response({'message': 'Invalid or expired token.'}, status=400)
    new_email = request.data.get('new_email')
    if not new_email:
        return Response({'message': 'Email is required.'}, status=400)
    
    if User.objects.filter(email=new_email).exclude(pk=user.pk).exists():
        return Response({'message': 'This email is already in use.'}, status=400)
    
    user.email = new_email
    user.save()
    return Response({'message': 'Email updated successfully.'}, status=200)


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        profile = get_object_or_404(Profile, user=user)
        serializer = ProfileSerializer(profile, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    



class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        user = request.user
        profile = get_object_or_404(Profile, user=user)
        serializer = ProfileSerializer(profile, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Profile updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Products(APIView):
    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsSellerOrSuperUser()]
        return [AllowAny()]

    def get(self, request):

        products = Product.objects.all().order_by('-num_of_sales')
        
        category = request.query_params.get('category')
        if category:
            products = products.filter(category__name__icontains=category)

        seller = request.query_params.get('seller')
        if seller:
            products = products.filter(seller__username__icontains=seller)

        price_max = request.query_params.get('price_max')
        if price_max:
            products = products.filter(Q(price__lte=price_max ) | Q(sale_price__lte=price_max))

        is_sale = request.query_params.get('is_sale')
        if is_sale:
            products = products.filter(is_sale=is_sale.lower() == 'true')
            
        is_available = request.query_params.get('is_available')
        if is_available:
            products = products.filter(is_available=is_available.lower() == 'true')

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
        return [IsSellerOrSuperUser()]
    
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

class ExtraFeaturesList(APIView):
    
    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsSellerOrSuperUser()]
        return [AllowAny()]

    def get(self, request, product_id):
        product = get_object_or_404(Product, pk=product_id)
        extra_features = product.extra_features.all()
        serializer = ExtraFeatureSerializer(extra_features, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request, product_id):
        product = get_object_or_404(Product, pk=product_id)
        serializer = ExtraFeatureSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(product=product)
            return Response({'message': 'Extra feature added successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class ExtraFeatureDetails(APIView):
    permission_classes = [IsSellerOrSuperUser]

    def put(self, request, product_id, pk):
        product = get_object_or_404(Product, pk=product_id)
        extra_feature = get_object_or_404(ExtraFeature, pk=pk, product=product)
        serializer = ExtraFeatureSerializer(extra_feature, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Extra feature updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, product_id, pk):
        product = get_object_or_404(Product, pk=product_id)
        extra_feature = get_object_or_404(ExtraFeature, pk=pk, product=product)
        extra_feature.delete()
        return Response({'message': 'Extra feature deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


class RelatedProducts(APIView):
    permission_classes = [AllowAny]

    def get(self, request, product_id):
        product = get_object_or_404(Product, pk=product_id)
        category = product.category
        related_products = Product.objects.filter(category=category).exclude(id=product.id).order_by('-num_of_sales')[:10]
        serializer = ProductSerializer(related_products, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK )
    
class SuggestedProducts(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        purchase = Purchase.objects.filter(user=user).first()
        if not purchase:
            return Response([], status=status.HTTP_200_OK)

        purchase_categories = set(
            purchase.products.values_list('category', flat=True).distinct()
        )

        products = Product.objects.filter(
            category__in=purchase_categories,
            category__isnull=False
        ).order_by('-num_of_sales')[:20]

        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


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
            customer_filter = request.query_params.get('customer')
            if customer_filter:
                orders = orders.filter(Q(user__username__icontains=customer_filter)| Q(user__email__icontains=customer_filter)| Q(user__first_name__icontains=customer_filter)| Q(user__last_name__icontains=customer_filter))
            status_filter = request.query_params.get('status')
            if status_filter:
                orders = orders.filter(status=status_filter)
            payment_status_filter = request.query_params.get('payment_status')
            if payment_status_filter:
                orders = orders.filter(payment_status=payment_status_filter)
            date_from = request.query_params.get('date_from')
            if date_from:
                orders = orders.filter(date_of_order__date__gte=date_from)
            date_to = request.query_params.get('date_to')
            if date_to:
                orders = orders.filter(date_of_order__date__lte=date_to)
        elif request.user.is_delivery:
            status_params = request.query_params.get('status', 'PENDING')
            orders = Order.objects.filter(status=status_params).order_by('date_of_order')
        else :
            orders = Order.objects.filter(user=request.user).order_by('date_of_order')
        pagenator = PageNumberPagination()
        pagenated_orders = pagenator.paginate_queryset(orders, request)
        serializer = OrderSerializer(pagenated_orders, many=True)

        response_data = {
            "orders": serializer.data,
        }
        if request.user.is_staff :
            response_data["total_orders"] = orders.count()
            total_amount = orders.aggregate(total_amount=models.Sum('total_price'))['total_amount'] or 0
            response_data["total_amount"] = total_amount

        return Response(response_data, status=status.HTTP_200_OK)
    

class Order_datails(APIView):

    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        order = get_object_or_404(Order, pk=pk)
        if self.request.user == order.user or self.request.user.is_staff or self.request.user.is_delivery:
            serializer = OrderSerializer(order, many=False)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'messaage':'This page is not allowed for you'}, status=status.HTTP_400_BAD_REQUEST)


def order_email(order):
    subject = 'Order Confirmation'
    html_message = render_to_string('email/order_confirmation.html', {'order': order})
    plain_message = strip_tags(html_message)
    email = EmailMultiAlternatives(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [order.user.email])
    email.attach_alternative(html_message, "text/html")
    email.send()

def order_admin_email(order):
    subject = 'New Order'
    html_message = render_to_string('email/new_order.html', {'order': order})
    plain_message = strip_tags(html_message)
    email = EmailMultiAlternatives(subject, plain_message, order.user.email, [settings.DEFAULT_FROM_EMAIL])
    email.attach_alternative(html_message, "text/html")
    email.send()

class OrderCreate(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = OrderSerializer(data=request.data, context={'request':request})
        if serializer.is_valid():
            order = serializer.save()
            order_email(order)
            order_admin_email(order)

            return Response({"message":"Order is created successfully"}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

def update_product_sales(order_items, add=True):
    for item in order_items:
        if item.product:
            if add:
                item.product.num_of_sales += item.quantity
            else:
                item.product.num_of_sales = max(0, item.product.num_of_sales - item.quantity)
            item.product.save()

def add_products_to_purchase(user, order_items):
    purchase, _ = Purchase.objects.get_or_create(user=user)
    existing_products = set(purchase.products.values_list('id', flat=True))
    for item in order_items:
        if item.product and item.product.id not in existing_products:
            purchase.products.add(item.product)
    purchase.save()

class OrderDeleviring(APIView):
    permission_classes = [IsDeliveryOrSuperUser]

    def put(self, request, pk):
        order = get_object_or_404(Order, pk=pk)
        cart, _ = Cart.objects.get_or_create(user=order.user)
        serializer = OrderDeleviringSerializer(order, data=request.data)
        if serializer.is_valid():
            serializer.save()
            order.refresh_from_db()

            if order.payment_status == 'PAID':
                cart.products.clear()

            order_items = order.order_items.all()
            if order.status == 'DELIVERED' and order.payment_status == 'PAID' :
                update_product_sales(order_items, add=True)
                add_products_to_purchase(order.user, order_items)
                
            elif order.status == 'RETRIEVED' and order.payment_status == 'REFUNDED' :
                update_product_sales(order_items, add=False)

            return Response({'message':'Order status updated'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PurchaseList(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        purchase = Purchase.objects.filter(user=user).order_by('-purchase_date')
        paginator = PageNumberPagination()
        pagenated_purchase = paginator.paginate_queryset(purchase, request)
        serializer = PurchaseSerializer(pagenated_purchase, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AddressList(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        addresses = Address.objects.filter(user=user)
        serializer = AddressSerializer(addresses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        user = request.user
        serializer = AddressSerializer(data=request.data, context={'request':request})
        if serializer.is_valid():
            serializer.save(user=user)
            return Response({'message':'Address created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class AddressDetails(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        user = request.user
        address = get_object_or_404(Address, pk=pk, user=user)
        serializer = AddressSerializer(address, data=request.data, context={'request':request}, partial=True) # Allow partial updates
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'Address updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        user = request.user
        address = get_object_or_404(Address, pk=pk, user=user)
        address.delete()
        return Response({'message':'Address deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

def seller_app_admin_email(application):
    subject = 'New application'
    html_message = render_to_string('email/new_application.html', {'application': application})
    plain_message = strip_tags(html_message)
    email = EmailMultiAlternatives(subject, plain_message, application.user.email, [settings.DEFAULT_FROM_EMAIL])
    email.attach_alternative(html_message, "text/html")
    email.send()

class SellerApp(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if SellersApplication.objects.filter(user=user, request_status__in=['PENDING', 'APPROVED']).exists():
            return Response({'message':'You already have an application'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = SellersApplicationSerializer(data=request.data, context={'request':request})
        if serializer.is_valid():
            serializer.save()
            seller_app_admin_email(serializer.instance) #--> serializer.instance is the application object
            return Response({'message':'Application submitted successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        user = request.user

        if user.is_staff:
            applications = SellersApplication.objects.all().order_by('-application_date')
            status_filter = request.query_params.get('status')
            if status_filter:
                applications = applications.filter(request_status=status_filter)
            seller_filter = request.query_params.get('seller')
            if seller_filter:
                applications = applications.filter(Q(user__username__icontains=seller_filter)| Q(user__email__icontains=seller_filter)| Q(user__first_name__icontains=seller_filter)| Q(user__last_name__icontains=seller_filter))
            paginator = PageNumberPagination()
            paginated_applications = paginator.paginate_queryset(applications, request)
            serializer = SellersApplicationSerializer(paginated_applications, many=True)
            response_data = {
                "applications": serializer.data,
                "total_applications": applications.count()
            }
            return Response(response_data, status=status.HTTP_200_OK)
        
        application = SellersApplication.objects.filter(user=user).order_by('-application_date')
        serializer = SellersApplicationSerializer(application, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

def seller_app_confimation_email(application):
    subject = 'Application Approved'
    html_message = render_to_string('email/app_approved.html', {'application': application})
    plain_message = strip_tags(html_message)
    email = EmailMultiAlternatives(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [application.user.email])
    email.attach_alternative(html_message, "text/html")
    email.send()

def seller_app_rejection_email(application):
    subject = 'Application Rejected'
    html_message = render_to_string('email/app_regection.html', {'application': application})
    plain_message = strip_tags(html_message)
    email = EmailMultiAlternatives(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [application.user.email])
    email.attach_alternative(html_message, "text/html")
    email.send()


class SellerAppDetails(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        application = get_object_or_404(SellersApplication, pk=pk)
        if request.user == application.user or request.user.is_staff:
            serializer = SellersApplicationSerializer(application, many=False)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({'detail':'This page is not allowed for you'}, status=status.HTTP_403_FORBIDDEN)
    
    def put(self, request, pk):
        application = get_object_or_404(SellersApplication, pk=pk)
        if request.user != application.user:
            return Response({'detail':'This page is not allowed for you'}, status=status.HTTP_403_FORBIDDEN)
        
        if application.request_status in ['APPROVED', 'REJECTED']:
            return Response({'detail': 'You cannot update an application that has already been reviewed'}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = SellersApplicationSerializer(application, data=request.data, context={'request':request}, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Application updated successfully','application': serializer.data}, status=status.HTTP_200_OK) # (to front) Return updated application data without ID or any sensitive info

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        application = get_object_or_404(SellersApplication, pk=pk)
        if request.user != application.user and not request.user.is_staff:
            return Response({'detail':'This page is not allowed for you'}, status=status.HTTP_403_FORBIDDEN)
        
        if application.request_status in ['APPROVED', 'REJECTED'] and not request.user.is_staff:
            return Response({'detail': 'You cannot delete an application that has already been reviewed'}, status=status.HTTP_400_BAD_REQUEST)
        
        application.delete()
        return Response({'detail':'Application deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


class SellerApproveReject(APIView):
    permission_classes = [IsAdminUser]

    def put(self, request, pk):
        application = get_object_or_404(SellersApplication, pk=pk)
        serializer = SellerConfirmationSerializer(application, data=request.data, context={'request':request}, partial=True)
        if serializer.is_valid():
            serializer.save()
            if serializer.instance.request_status == 'APPROVED':
                seller_app_confimation_email(serializer.instance)
            elif serializer.instance.request_status == 'REJECTED':
                seller_app_rejection_email(serializer.instance)
            else :
                pass
            return Response({'detail': 'Application status updated successfully','application': serializer.data}, status=status.HTTP_200_OK) # (to front) Return updated application data without ID or any sensitive info

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
