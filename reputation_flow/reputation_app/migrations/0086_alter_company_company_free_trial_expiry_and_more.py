# Generated by Django 4.2.16 on 2024-12-26 17:35

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0085_alter_company_company_free_trial_expiry_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 31, 17, 35, 57, 684358, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_subscription_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 26, 17, 35, 57, 684358, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 24, 17, 35, 57, 694357, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 24, 17, 35, 57, 693540, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 24, 17, 35, 57, 696358, tzinfo=datetime.timezone.utc)),
        ),
    ]
