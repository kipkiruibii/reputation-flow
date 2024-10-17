# Generated by Django 4.2.16 on 2024-10-15 10:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0009_companyprofilepicture'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='company_active_subscription',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='company',
            name='company_free_trial',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='company',
            name='company_subscription',
            field=models.TextField(default=''),
        ),
    ]
