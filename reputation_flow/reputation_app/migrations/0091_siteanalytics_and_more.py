# Generated by Django 4.2.16 on 2024-12-31 05:56

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0090_alter_company_company_free_trial_expiry_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='SiteAnalytics',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('page_visited', models.TextField(default='')),
                ('device', models.TextField(default='')),
                ('date_visited', models.DateTimeField(default=datetime.datetime(2024, 12, 31, 5, 56, 39, 516427, tzinfo=datetime.timezone.utc))),
                ('request_header', models.TextField(default='')),
                ('country', models.TextField(default='')),
                ('location', models.JSONField(default='')),
                ('is_vpn', models.BooleanField(default=False)),
            ],
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2025, 1, 5, 5, 56, 39, 516427, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_subscription_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 31, 5, 56, 39, 516427, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companybotchats',
            name='date_sent',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 31, 5, 56, 39, 516427, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 3, 1, 5, 56, 39, 516427, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 3, 1, 5, 56, 39, 516427, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 3, 1, 5, 56, 39, 516427, tzinfo=datetime.timezone.utc)),
        ),
    ]
