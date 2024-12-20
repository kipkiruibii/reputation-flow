# Generated by Django 4.2.16 on 2024-10-30 21:31

import datetime
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0026_alter_company_company_free_trial_expiry_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='companyinstagram',
            old_name='token',
            new_name='account_id',
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='account_name',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='account_type',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='company',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='reputation_app.company'),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='followers_trend',
            field=models.JSONField(default={}),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='impressions',
            field=models.JSONField(default={}),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='last_update_time',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='long_lived_token',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='profile_url',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='profile_views',
            field=models.JSONField(default={}),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='reach',
            field=models.JSONField(default={}),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='short_lived_token',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2024, 12, 29, 21, 31, 47, 983087, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 4, 21, 31, 47, 977086, tzinfo=datetime.timezone.utc)),
        ),
    ]
