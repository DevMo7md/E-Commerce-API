from typing import Iterable
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.conf import settings
import uuid
from decimal import Decimal
from django.utils import timezone
class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    is_seller = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    is_delivery = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.email} ({self.username})'

class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Address(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='addresses')
    government = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    street = models.CharField(max_length=200)
    zip_code = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.street}, {self.city}, {self.government}, {self.zip_code}"

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    fullname = models.CharField(max_length=200)
    phone_num = models.CharField(max_length=20)

    def __str__(self):
        return self.fullname
    

class Product(models.Model):
    name = models.CharField(max_length=200)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    photo = models.ImageField(upload_to='products/', null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    is_available = models.BooleanField(default=True)
    is_sale = models.BooleanField(default=False)
    sale_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    seller = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='products')
    sale_percentage = models.PositiveIntegerField(default=0)
    brand = models.CharField(max_length=100,null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    quantity = models.PositiveIntegerField(default=1, null=True, blank=True)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    num_of_sales = models.PositiveIntegerField(default=0)
    weight = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.is_sale and self.sale_percentage != 0 :
            discount = Decimal(self.sale_percentage) / Decimal('100')
            self.sale_price = self.price * (Decimal('1') - discount)
        else:
            self.sale_price = None
            
        super().save(*args, **kwargs)

        self.refresh_from_db(fields=["quantity"])

        if self.quantity <= 0:
            self.is_available = False
        else:
            self.is_available = True

        super().save(update_fields=["is_available"])

    def __str__(self):
        return self.name

class ExtraFeature(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='extra_features')
    feature_name = models.CharField(max_length=100)
    feature_value = models.CharField(max_length=200)

    def __str__(self):
        return f"{self.feature_name}: {self.feature_value} for {self.product.name}"


class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reviews')
    rate = models.PositiveSmallIntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review by {self.user.email} for {self.product.name}"

class Cart(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    products = models.ManyToManyField(Product, through='CartItem')

    def __str__(self):
        return f"Cart of {self.user.email}"

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='cart_items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='products')
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.quantity} x {self.product.name}"

class PaymentStatus(models.TextChoices):
    PENDING = 'PENDING', 'قيد الانتظار'
    PAID = 'PAID', 'تم الدفع'
    FAILED = 'FAILED', 'فشل'
    REFUNDED = 'REFUNDED', 'تم استرداد المبلغ'

class OrderStatus(models.TextChoices):
    PENDING = 'PENDING', 'قيد التوصيل'
    DELIVERED = 'DELIVERED', 'تم التوصيل'
    FAILED = 'FAILED', 'فشل التوصيل'
    RETRIEVED = 'RETRIEVED', 'تم الاسترجاع'

class ShippingStatus(models.TextChoices):
    ON_DELIVERED = 'ON_DELIVERED', 'الدفع عند التوصيل'
    CARD = 'CARD', 'بالفيزا'



class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='orders')
    address = models.ForeignKey(Address, on_delete=models.SET_NULL, null=True)
    date_of_order = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(max_length=50, choices=PaymentStatus.choices, default=PaymentStatus.PENDING)
    status = models.CharField(max_length=50, choices=OrderStatus.choices, default=OrderStatus.PENDING)
    shipping_status = models.CharField(max_length=50, choices=ShippingStatus.choices, default=ShippingStatus.ON_DELIVERED)
    coupon_code = models.CharField(max_length=50, null=True, blank=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    total_items = models.PositiveIntegerField(null=True, blank=True)
    total_weight = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)


    def __str__(self):
        return f"Order #{self.id} by {self.user.email}"

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='order_items')
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.quantity} x {self.product.name}"

class Purchase(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='purchases')
    products = models.ManyToManyField(Product)
    purchase_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Purchase by {self.user.email} on {self.purchase_date}"


class SellerAppStatus(models.TextChoices):
    PENDING = 'PENDING', 'جاري المراجعة'
    REJECTED = 'REJECTED', 'مرفوض'
    APPROVED = 'APPROVED', 'مقبول'

class SellersApplication(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='seller_applications')
    full_name = models.CharField(max_length=200)
    business_name = models.CharField(max_length=200, null=True, blank=True)
    phone_number = models.CharField(max_length=20)
    address = models.TextField()
    description = models.TextField()
    application_date = models.DateTimeField(auto_now_add=True)
    request_status = models.CharField(max_length=50, choices=SellerAppStatus.choices, default=SellerAppStatus.PENDING)
    rejection_reason = models.TextField(null=True, blank=True)
    #documents

    def __str__(self):
        return f"Seller Application by {self.user.email}"
    
class SellerDocuments(models.Model):
    application = models.ForeignKey(SellersApplication, on_delete=models.CASCADE, related_name='documents')
    document = models.FileField(upload_to='seller_documents/') # 3 Documents (ID(front), ID(back), ID(Selfie))
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Document for {self.application.user.email} uploaded at {self.uploaded_at}" 
    

class Coupon(models.Model):
    seller = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='coupons', null=True, blank=True)
    code = models.CharField(max_length=50, unique=True)
    discount_percentage = models.PositiveIntegerField()
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    manually_disabled = models.BooleanField(default=False)
    limit_per_user = models.PositiveIntegerField(default=1)
    times_used = models.PositiveIntegerField(default=0)
    limit = models.PositiveIntegerField(default=50)

    def __str__(self):
        return self.code
    
    @property
    def is_active(self):
        now = timezone.now()
        return (self.valid_from <= now <= self.valid_to) and not self.manually_disabled and self.times_used < self.limit
    
    
class Occasion(models.Model):
    seller = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='occasions', null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    manually_disabled = models.BooleanField(default=False)


    def __str__(self):
        return self.name
    
    @property
    def is_active(self):
        now = timezone.now()
        return (self.start_date <= now <= self.end_date) and not self.manually_disabled
    