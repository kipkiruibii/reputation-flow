# Generated by Django 4.2.16 on 2024-10-15 18:12

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0014_alter_company_company_free_trial_expiry'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='company_link_name',
            field=models.CharField(default='link', max_length=255),
        ),
        migrations.AddField(
            model_name='companycontacts',
            name='tiktok',
            field=models.TextField(default='', null=True),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 10, 20, 18, 12, 47, 587379, tzinfo=datetime.timezone.utc)),
        ),
    ]
