from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model
User = get_user_model()
from django.shortcuts import get_object_or_404, get_list_or_404
from decimal import Decimal

from django.db.models import F
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
    government = serializers.CharField(required=True)
    city = serializers.CharField(required=True)
    street = serializers.CharField(required=True)
    zip_code = serializers.CharField(required=True)
    class Meta:
        model = Address
        fields = ['id', 'user', 'government', 'city', 'street', 'zip_code']
        read_only_fields = ['id', 'user']

    def validate(self, data):
        user = self.context['request'].user
        if not self.instance and Address.objects.filter(user=user).count() >= 3:
            raise serializers.ValidationError("A user can have only 3 addresses.")
        return data
        

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
        fields = ['id', 'product', 'user', 'rate', 'comment', 'created_at'
        ]
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
        fields = ['id', 'user', 'products', 'cart_items'
        ]
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
            'total_price', 'total_items', 'order_items', 'items', 'shipping_status', 'total_weight', 'coupon_code'
        ]
        read_only_fields = ['id', 'date_of_order', 'total_items', 'total_price', 'user' , 'payment_status','status', 'total_weight', 'shipping_status', 'coupon_code']

    def create(self, validated_data):
        user = self.context['request'].user
        address = get_object_or_404(Address, user=user)

        items_data = self.context['request'].data.get('items', [])
        coupon_code = self.context['request'].data.get('coupon_code')
        total_price = Decimal('0.0')
        total_items = 0
        total_weight = Decimal('0.0')
        order_items_data = []

        products_price_list = []  # [(product, quantity, price_per_unit)]

        # Validate stock and prepare order items
        for item_data in items_data:
            product = get_object_or_404(Product, id=item_data['product_id'])
            quantity = item_data['quantity']

            if product.quantity < quantity:
                raise serializers.ValidationError(
                    f"Not enough stock for product {product.name}. Available: {product.quantity}, Requested: {quantity}"
                )

            total_weight += Decimal(str(product.weight)) * Decimal(str(quantity))
            order_items_data.append({'product': product, 'quantity': quantity})

            total_items += quantity

            price_per_unit = product.sale_price if product.is_sale and product.sale_price else product.price
            products_price_list.append((product, quantity, price_per_unit))

        # Coupon logic: apply discount if coupon_code is provided and valid
        applied_coupon_code = None
        if coupon_code:
            try:
                coupon = Coupon.objects.get(code=coupon_code, manually_disabled=False)
                now = timezone.now()
                if not (coupon.valid_from <= now <= coupon.valid_to):
                    raise serializers.ValidationError("Coupon is expired or not yet valid.")

                # Check limit_per_user
                user_coupon_count = Order.objects.filter(user=user, coupon_code=coupon.code).count()
                if user_coupon_count >= coupon.limit_per_user:
                    raise serializers.ValidationError("You have reached the usage limit for this coupon.")

                discount = Decimal(coupon.discount_percentage) / Decimal('100')
                applied_coupon_code = coupon.code

                if coupon.seller:
                    # Discount only on products from this seller
                    for product, quantity, price_per_unit in products_price_list:
                        if product.seller == coupon.seller:
                            total_price += quantity * price_per_unit * (Decimal('1') - discount)
                        else:
                            total_price += quantity * price_per_unit
                else:
                    # Discount on all products
                    for product, quantity, price_per_unit in products_price_list:
                        total_price += quantity * price_per_unit * (Decimal('1') - discount)
            except Coupon.DoesNotExist:
                raise serializers.ValidationError("Invalid coupon code.")
        else:
            # No coupon, normal price
            for product, quantity, price_per_unit in products_price_list:
                total_price += quantity * price_per_unit

        # All validations passed, now create the order and order items
        order = Order.objects.create(
            user=user,
            address=address,
            total_items=total_items,
            total_price=total_price,
            total_weight=total_weight,
            coupon_code=applied_coupon_code
        )

        order_items = []
        for item in order_items_data:
            product = item['product']
            quantity = item['quantity']
            order_items.append(OrderItem(order=order, product=product, quantity=quantity))
            # Update product stock
            product.quantity = F('quantity') - quantity
            product.save()
            product.refresh_from_db()

        OrderItem.objects.bulk_create(order_items)

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


class SellersApplicationSerializer(serializers.ModelSerializer):

    documents = serializers.ListField(
        child=serializers.FileField(), write_only=True, required=False
    ) # For uploading new documents
    uploaded_documents = serializers.SerializerMethodField(read_only=True) # To display existing documents
    class Meta:
        model = SellersApplication
        fields = ['id', 'user', 'full_name', 'business_name', 'address', 'phone_number', 'description', 'request_status', 'application_date', 'documents', 'uploaded_documents', 'rejection_reason']
        read_only_fields = ['id', 'user', 'request_status', 'application_date', 'rejection_reason']
        
    def get_uploaded_documents(self, obj):
        return [doc.document.url for doc in obj.documents.all()]
    
    def validate_documents(self, value):
        if len(value) > 3:
            raise serializers.ValidationError("You can upload a maximum of 3 documents.")
        return value

    def create(self, validated_data):
        user = self.context['request'].user
        documents = validated_data.pop('documents', [])

        applications = SellersApplication.objects.filter(user=user, request_status__in=['PENDING', 'APPROVED'])
        if applications.exists():
            raise serializers.ValidationError("You have already applied to be a seller.")
        
        application = SellersApplication.objects.create(user=user, **validated_data)

        for document in documents:
            SellerDocuments.objects.create(application=application, document=document)

        return application
    
    def update(self, instance, validated_data):
        documents = validated_data.pop('documents', [])

        # تحديث الحقول العادية
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # التعامل مع المستندات
        existing_docs_count = instance.documents.count()
        if existing_docs_count + len(documents) > 3:
            raise serializers.ValidationError("You can upload a maximum of 3 documents per application.")

        # إضافة المستندات الجديدة
        for doc in documents:
            SellerDocuments.objects.create(application=instance, document=doc)

        return instance


class SellerConfirmationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SellersApplication
        fields = ['request_status', 'rejection_reason']
        read_only_fields = []

    
    def update(self, instance, validated_data):

        previous_status = instance.request_status
        instance.request_status = validated_data.get('request_status', instance.request_status)
        instance.rejection_reason = validated_data.get('rejection_reason', instance.rejection_reason)
        instance.save()

        if previous_status != instance.request_status and instance.request_status == 'APPROVED':
            user = instance.user
            user.is_seller = True
            user.save()
        return instance
    

class CouponSerializer(serializers.ModelSerializer):
    class Meta:
        model = Coupon
        fields = ['id', 'code', 'discount_percentage', 'valid_from', 'valid_to', 'created_by', 'manually_disabled', 'is_active', 'seller']
        read_only_fields = ['id', 'created_by', 'is_active']
        extra_kwargs = {
            'created_by': {'required': False}
        }

    def validate_discount_percentage(self, value):
        if value > 100:
            raise serializers.ValidationError("Discount percentage cannot be more than 100%.")
        return value

    def validate(self, data):
            valid_from = data.get('valid_from', getattr(self.instance, 'valid_from', None))
            valid_to = data.get('valid_to', getattr(self.instance, 'valid_to', None))

            # وقت الـ create لازم الاتنين يكونوا موجودين
            if not self.instance and (not valid_from or not valid_to):
                raise serializers.ValidationError("Both valid_from and valid_to are required when creating a coupon.")

            # الشرط العام للتحقق من التواريخ
            if valid_from and valid_to and valid_to <= valid_from:
                raise serializers.ValidationError("valid_to must be greater than valid_from.")

            return data
    
class OccasionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Occasion
        fields = ['id', 'name', 'description', 'start_date', 'end_date', 'created_by', 'manually_disabled', 'is_active', 'seller']
        read_only_fields = ['id', 'created_by', 'is_active']
        extra_kwargs = {
            'created_by': {'required': False}
        }

    def validate(self, data):
            start_date = data.get('start_date', getattr(self.instance, 'start_date', None))
            end_date = data.get('end_date', getattr(self.instance, 'end_date', None))

            # وقت الـ create لازم الاتنين يكونوا موجودين
            if not self.instance and (not start_date or not end_date):
                raise serializers.ValidationError("Both start_date and end_date are required when creating an occasion.")

            # الشرط العام للتحقق من التواريخ
            if start_date and end_date and end_date <= start_date:
                raise serializers.ValidationError("end_date must be greater than start_date.")

            return data