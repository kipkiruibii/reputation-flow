# Generated by Django 4.2.16 on 2024-12-26 19:46

import datetime
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0089_company_company_enable_ai_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 31, 19, 46, 26, 220828, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='company',
            name='company_subscription_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 26, 19, 46, 26, 220828, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 24, 19, 46, 26, 226922, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 24, 19, 46, 26, 225791, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 24, 19, 46, 26, 226922, tzinfo=datetime.timezone.utc)),
        ),
        migrations.CreateModel(
            name='CompanyBotChats',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sender', models.TextField(blank=True, default='', null=True)),
                ('message', models.TextField(blank=True, default='', null=True)),
                ('date_sent', models.DateTimeField(default=datetime.datetime(2024, 12, 26, 19, 46, 26, 220828, tzinfo=datetime.timezone.utc))),
                ('conversation_id', models.TextField(blank=True, default='', null=True)),
                ('company', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reputation_app.company')),
            ],
        ),
    ]
