# Generated by Django 5.0.1 on 2024-02-10 14:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0011_onetimepassword_attemts_onetimepassword_created_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='onetimepassword',
            name='code',
            field=models.CharField(max_length=6),
        ),
    ]