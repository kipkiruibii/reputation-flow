# Generated by Django 4.2.16 on 2024-11-19 14:41

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0049_alter_company_company_free_trial_expiry_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='companyredditposts',
            name='agg_comment_count',
        ),
        migrations.RemoveField(
            model_name='companyredditposts',
            name='agg_impression_count',
        ),
        migrations.RemoveField(
            model_name='companyredditposts',
            name='agg_like_count',
        ),
        migrations.RemoveField(
            model_name='companyredditposts',
            name='agg_views_count',
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 24, 14, 41, 25, 161716, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 18, 14, 41, 25, 166716, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 18, 14, 41, 25, 166716, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 18, 14, 41, 25, 167716, tzinfo=datetime.timezone.utc)),
        ),
    ]
