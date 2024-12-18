# Generated by Django 4.2.16 on 2024-12-03 10:00

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0067_companyposts_has_failed_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyposts',
            name='failure_reasons',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 8, 10, 0, 51, 684055, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 1, 10, 0, 51, 689054, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 1, 10, 0, 51, 688055, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 1, 10, 0, 51, 690055, tzinfo=datetime.timezone.utc)),
        ),
    ]
