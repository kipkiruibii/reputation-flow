# Generated by Django 4.2.16 on 2024-12-06 23:26

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0072_companyposts_media_thumbnail_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyfacebookposts',
            name='parent_post_id',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 11, 23, 25, 59, 666263, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 4, 23, 25, 59, 671263, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 4, 23, 25, 59, 670430, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 4, 23, 25, 59, 671263, tzinfo=datetime.timezone.utc)),
        ),
    ]
