# Generated by Django 4.2.16 on 2024-11-13 18:00

import datetime
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0034_rename_account_id_companyreddit_comment_karma_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyFacebookPosts',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('post_id', models.CharField(max_length=255)),
                ('is_scheduled', models.BooleanField(default=False)),
                ('to_stories', models.BooleanField(default=False)),
                ('to_reels', models.BooleanField(default=False)),
                ('to_posts', models.BooleanField(default=False)),
                ('run_copyright', models.BooleanField(default=True)),
                ('has_copyright', models.BooleanField(default=False)),
                ('is_published', models.BooleanField(default=False)),
                ('comment_count', models.IntegerField(default=0)),
                ('like_count', models.IntegerField(default=0)),
                ('impression_count', models.IntegerField(default=0)),
                ('engagement_count', models.IntegerField(default=0)),
                ('views_count', models.IntegerField(default=0)),
                ('location_tags', models.TextField(default='')),
                ('product_tags', models.TextField(default='')),
                ('post_link', models.TextField(default='')),
            ],
        ),
        migrations.CreateModel(
            name='CompanyInstagramPosts',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('post_id', models.CharField(max_length=255)),
                ('is_scheduled', models.BooleanField(default=False)),
                ('to_stories', models.BooleanField(default=False)),
                ('to_reels', models.BooleanField(default=False)),
                ('to_posts', models.BooleanField(default=False)),
                ('run_copyright', models.BooleanField(default=True)),
                ('has_copyright', models.BooleanField(default=False)),
                ('is_published', models.BooleanField(default=False)),
                ('comment_count', models.IntegerField(default=0)),
                ('like_count', models.IntegerField(default=0)),
                ('impression_count', models.IntegerField(default=0)),
                ('engagement_count', models.IntegerField(default=0)),
                ('views_count', models.IntegerField(default=0)),
                ('location_tags', models.TextField(default='')),
                ('product_tags', models.TextField(default='')),
                ('post_link', models.TextField(default='')),
            ],
        ),
        migrations.CreateModel(
            name='CompanyRedditPosts',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('post_id', models.CharField(max_length=255)),
                ('is_scheduled', models.BooleanField(default=False)),
                ('to_stories', models.BooleanField(default=False)),
                ('to_reels', models.BooleanField(default=False)),
                ('to_posts', models.BooleanField(default=False)),
                ('subs', models.JSONField(default=dict)),
                ('post_link', models.TextField(default='')),
                ('agg_comment_count', models.IntegerField(default=0)),
                ('agg_like_count', models.IntegerField(default=0)),
                ('agg_impression_count', models.IntegerField(default=0)),
                ('agg_engagement_count', models.IntegerField(default=0)),
                ('agg_views_count', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='CompanyTiktokPosts',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('post_id', models.CharField(max_length=255)),
                ('is_scheduled', models.BooleanField(default=False)),
                ('to_stories', models.BooleanField(default=False)),
                ('to_reels', models.BooleanField(default=False)),
                ('to_posts', models.BooleanField(default=False)),
                ('run_copyright', models.BooleanField(default=True)),
                ('has_copyright', models.BooleanField(default=False)),
                ('is_published', models.BooleanField(default=False)),
                ('comment_count', models.IntegerField(default=0)),
                ('location_tags', models.TextField(default='')),
                ('product_tags', models.TextField(default='')),
                ('post_link', models.TextField(default='')),
                ('engagement_count', models.IntegerField(default=0)),
            ],
        ),
        migrations.RenameField(
            model_name='companyposts',
            old_name='content',
            new_name='description',
        ),
        migrations.RemoveField(
            model_name='companyposts',
            name='is_uploaded',
        ),
        migrations.AddField(
            model_name='companyposts',
            name='date_scheduled',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='companyposts',
            name='post_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='companyposts',
            name='title',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 18, 18, 0, 9, 408184, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='followers_trend',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='impressions',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='page_engaged_users',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='page_fans',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='page_negative_feedback',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='page_views_total',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='profile_views',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='reach',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 12, 18, 0, 9, 413295, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='followers_trend',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='impressions',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='reach',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 12, 18, 0, 9, 413295, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyposts',
            name='platforms',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyposts',
            name='tags',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companyteaminvitelinks',
            name='permissions',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='followers_count',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='likes_count',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='profile_views',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='reach',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 1, 12, 18, 0, 9, 414183, tzinfo=datetime.timezone.utc)),
        ),
    ]
