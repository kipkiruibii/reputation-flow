# Generated by Django 4.2.16 on 2024-10-15 08:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0007_alter_companymember_permissions'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='company_about',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_address2',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_website',
            field=models.TextField(blank=True, default='', null=True),
        ),
    ]
