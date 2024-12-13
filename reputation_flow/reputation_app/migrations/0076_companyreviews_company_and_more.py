# Generated by Django 4.2.16 on 2024-12-12 07:35

import datetime
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0075_companyreviews_is_negative_companyreviews_is_neutral_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyreviews',
            name='company',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='reputation_app.company'),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 17, 7, 35, 17, 847491, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 10, 7, 35, 17, 853496, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 10, 7, 35, 17, 853496, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 10, 7, 35, 17, 854459, tzinfo=datetime.timezone.utc)),
        ),
    ]
