# Generated by Django 5.0.1 on 2024-02-06 10:39

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0004_remove_customuser_expiry_date_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.PositiveIntegerField(validators=[django.core.validators.MinValueValidator(100000), django.core.validators.MaxValueValidator(999999)])),
                ('time_created', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AlterField(
            model_name='customuser',
            name='otp',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='account.otp'),
        ),
    ]