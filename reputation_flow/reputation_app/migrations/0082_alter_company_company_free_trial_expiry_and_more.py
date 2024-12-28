# Generated by Django 4.2.16 on 2024-12-25 15:06

import datetime
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0081_company_company_subscription_tier_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 30, 15, 6, 19, 862770, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_subscription_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 25, 15, 6, 19, 862770, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 23, 15, 6, 19, 868770, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 23, 15, 6, 19, 867770, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 23, 15, 6, 19, 869770, tzinfo=datetime.timezone.utc)),
        ),
        migrations.CreateModel(
            name='CompanyFeatureRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.TextField(default='')),
                ('details', models.TextField(default='')),
                ('date_created', models.DateTimeField(default=django.utils.timezone.now)),
                ('company', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reputation_app.company')),
            ],
        ),
    ]