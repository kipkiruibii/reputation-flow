# Generated by Django 4.2.16 on 2024-10-25 22:58

import datetime
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0023_companyteaminvitelinks_date_created_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyTeamFiles',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('creator_id', models.CharField(max_length=255)),
                ('file_name', models.TextField(default='')),
                ('description', models.TextField(default='')),
                ('not_sent', models.BooleanField(default=True)),
                ('sent_drafts', models.BooleanField(default=False)),
                ('sent_back', models.BooleanField(default=False)),
                ('approved', models.BooleanField(default=False)),
                ('date_created', models.DateTimeField(default=django.utils.timezone.now)),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reputation_app.companyteam')),
            ],
        ),
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 10, 30, 22, 58, 51, 397060, tzinfo=datetime.timezone.utc)),
        ),
        migrations.CreateModel(
            name='UploadedFiles',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='uploaded_files/')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reputation_app.companyteamfiles')),
            ],
        ),
    ]
