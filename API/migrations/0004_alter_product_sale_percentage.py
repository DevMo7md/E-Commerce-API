# Generated by Django 5.2.4 on 2025-07-14 22:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('API', '0003_product_sale_percentage'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='sale_percentage',
            field=models.PositiveBigIntegerField(default=0),
        ),
    ]
