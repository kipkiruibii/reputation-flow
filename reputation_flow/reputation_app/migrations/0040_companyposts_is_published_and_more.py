# Generated by Django 4.2.16 on 2024-11-14 19:14

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0039_rename_to_posts_companyredditposts_nsfw_tag_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyposts',
            name='is_published',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 19, 19, 14, 57, 751393, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 13, 19, 14, 57, 760465, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 13, 19, 14, 57, 759468, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 13, 19, 14, 57, 761467, tzinfo=datetime.timezone.utc)),
        ),
    ]