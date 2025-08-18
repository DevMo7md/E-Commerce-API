from rest_framework import serializers
from .models import (
    CustomUser, Category, Address, Profile, Product, Review, Cart, CartItem, Order, OrderItem, Purchase, ExtraFeature
)
from django.contrib.auth import get_user_model
User = get_user_model()
from django.shortcuts import get_object_or_404

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name','last_name' ,'password','phone_number','address')

    def create(self, validated_data):
        user = User(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_number=validated_data['phone_number'],
            address=validated_data['address'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'phone_number', 'address', 'is_seller', 'is_delivery']
        read_only_fields = ['id']

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']
        read_only_fields = ['id']

class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['id', 'user', 'government', 'city', 'street', 'zip_code']
        read_only_fields = ['id']

class ProfileSerializer(serializers.ModelSerializer):
    address = AddressSerializer(read_only=True)
    user = CustomUserSerializer(read_only=True)
    purchases = serializers.SerializerMethodField()
    class Meta:
        model = Profile
        fields = ['id', 'user', 'fullname', 'phone_num', 'address', 'purchases']
        read_only_fields = ['id']

    def get_purchases(self, obj):
        purchases = Purchase.objects.filter(user=obj.user)
        return PurchaseSerializer(purchases, many=True).data

class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ['id', 'product', 'user', 'rate', 'comment', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']

    def create(self, validated_data):
        user = self.context["request"].user
        return Review.objects.create(user=user, **validated_data)
    
    def validate_rate(self, value):
        if not (1 <= value <= 5):
            raise serializers.ValidationError("Rate must be between 1 and 5")
        return value


class ExtraFeatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExtraFeature
        fields = ['id', 'product', 'feature_name', 'feature_value']
        read_only_fields = ['id', 'product']

class ProductSerializer(serializers.ModelSerializer):
    reviews = ReviewSerializer(many=True, read_only=True)
    category_detail = CategorySerializer(read_only=True, source='category')
    extra_features = ExtraFeatureSerializer(many=True, read_only=True)
    class Meta:
        model = Product
        fields = [
            'id', 'name', 'price', 'photo', 'description', 'is_available', 'quantity', 'is_sale',
            'sale_percentage','sale_price', 'seller', 'brand', 'created_at', 'category', 'reviews', 'num_of_sales', 'category_detail', 'extra_features', 'weight'
        ]
        read_only_fields = ['id', 'created_at', 'sale_price', 'num_of_sales', 'extra_features']

    def create(self, validated_data):
        user = self.context["request"].user
        return Product.objects.create(seller=user, **validated_data)


class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(many=False, read_only=True)
    class Meta:
        model = CartItem
        fields = ['id', 'cart', 'product', 'quantity']
        read_only_fields = ['id', 'cart']

    def update(self, instance, validated_data):
        instance.quantity = validated_data.get('quantity', instance.quantity)
        
        if instance.quantity == 0:
            instance.delete()
        else:
            instance.save()
        return instance

class CartSerializer(serializers.ModelSerializer):
    cart_items = CartItemSerializer(many=True, read_only=True)
    class Meta:
        model = Cart
        fields = ['id', 'user', 'products', 'cart_items']
        read_only_fields = ['id']


class OrderItemSerializer(serializers.ModelSerializer):
    product_id = serializers.IntegerField()
    class Meta:
        model = OrderItem
        fields = ['id', 'order', 'product', 'product_id', 'quantity']
        read_only_fields = ['id', 'order', 'product']

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, write_only=True)# for POST
    order_items = OrderItemSerializer(many=True, read_only=True)# for GET
    address = AddressSerializer(read_only=True)
    class Meta:
        model = Order
        fields = [
            'id', 'user', 'address', 'date_of_order', 'payment_status','status', 
            'total_price', 'total_items', 'order_items', 'items', 'shipping_status'
        ]
        read_only_fields = ['id', 'date_of_order', 'total_items', 'total_price', 'user' , 'payment_status','status']

    def create(self, validated_data):
        user = self.context['request'].user
        address = get_object_or_404(Address, user=user)

        order = Order.objects.create(user=user, address=address)

        items_data = self.context['request'].data.get('items', [])
        total_price = 0
        total_items = 0

        for item_data in items_data:
            product = get_object_or_404(Product, id=item_data['product_id'])
            quantity = item_data['quantity']
            OrderItem.objects.create(order=order, product=product, quantity=quantity)

            total_items += quantity
            if product.is_sale and product.sale_price:
                total_price += quantity * product.sale_price
            else:
                total_price += quantity * product.price

        order.total_items = total_items
        order.total_price = total_price
        if order.shipping_status == 'ON_DELIVERED':
            order.payment_status = 'PAID'
        order.save()
        cart, _ = Cart.objects.get_or_create(user=order.user)
        if order.payment_status == 'PAID':
                cart.products.clear()
                cart.save()
        return order

class OrderDeleviringSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['payment_status' ,'status']

class PurchaseSerializer(serializers.ModelSerializer):
    products = ProductSerializer(many=True, read_only=True)
    class Meta:
        model = Purchase
        fields = ['id', 'user', 'products', 'purchase_date']
        read_only_fields = ['id', 'purchase_date']
