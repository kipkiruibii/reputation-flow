# Generated by Django 4.2.16 on 2024-12-25 17:02

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0083_companyfeaturerequest_feature_introduced_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='company_review_link',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='company',
            name='company_show_page',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 30, 17, 2, 40, 202811, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_subscription_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 25, 17, 2, 40, 202811, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 23, 17, 2, 40, 208811, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 23, 17, 2, 40, 207813, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 23, 17, 2, 40, 208811, tzinfo=datetime.timezone.utc)),
        ),
    ]
