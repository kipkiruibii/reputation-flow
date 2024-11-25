# Generated by Django 4.2.16 on 2024-11-16 21:42

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0045_alter_company_company_free_trial_expiry_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyreddit',
            name='subs',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 21, 21, 42, 41, 603247, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 15, 21, 42, 41, 610246, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 15, 21, 42, 41, 610246, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 15, 21, 42, 41, 611247, tzinfo=datetime.timezone.utc)),
        ),
    ]