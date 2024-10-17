# Generated by Django 4.2.16 on 2024-10-15 18:52

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0015_company_company_link_name_companycontacts_tiktok_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='company_address',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 10, 20, 18, 52, 17, 496784, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_phone',
            field=models.CharField(blank=True, max_length=30, null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='email',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='facebook',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='instagram',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='linkedin',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='tiktok',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='twitter',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='whatsapp',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='companycontacts',
            name='youtube',
            field=models.TextField(blank=True, default='', null=True),
        ),
    ]
