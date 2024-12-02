# Generated by Django 4.2.16 on 2024-11-30 21:33

import datetime
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0059_remove_companyfacebook_page_engaged_users_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='companypostscomments',
            name='author',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='companypostscomments',
            name='comment_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='companypostscomments',
            name='date_updated',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='companypostscomments',
            name='is_published',
            field=models.BooleanField(blank=True, default=False, null=True),
        ),
        migrations.AddField(
            model_name='companypostscomments',
            name='like_count',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AddField(
            model_name='companypostscomments',
            name='message',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AddField(
            model_name='companypostscomments',
            name='platform',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='companypostscomments',
            name='reply_count',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 5, 21, 33, 46, 891958, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 29, 21, 33, 46, 897958, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 29, 21, 33, 46, 896957, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 29, 21, 33, 46, 897958, tzinfo=datetime.timezone.utc)),
        ),
    ]
