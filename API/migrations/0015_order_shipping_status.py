# Generated by Django 5.2.4 on 2025-07-26 02:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('API', '0014_alter_order_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='shipping_status',
            field=models.CharField(choices=[('ON_DELIVERED', 'الدفع عند التوصيل'), ('CARD', 'بالفيزا')], default='ON_DELIVERED', max_length=50),
        ),
    ]
