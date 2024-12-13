# Generated by Django 4.2.16 on 2024-12-11 15:32

import datetime
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('reputation_app', '0073_companyfacebookposts_parent_post_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='company_free_trial_expiry',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 16, 15, 32, 15, 532603, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyfacebook',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 9, 15, 32, 15, 538583, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companyinstagram',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 9, 15, 32, 15, 538583, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='companytiktok',
            name='token_expiry',
            field=models.DateField(default=datetime.datetime(2025, 2, 9, 15, 32, 15, 539582, tzinfo=datetime.timezone.utc)),
        ),
        migrations.CreateModel(
            name='CompanyKnowledgeBase',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('training_done', models.BooleanField(default=False)),
                ('training_inprogress', models.BooleanField(default=False)),
                ('date_uploaded', models.DateTimeField(default=django.utils.timezone.now)),
                ('file', models.FileField(upload_to='training_data/')),
                ('company', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='reputation_app.company')),
            ],
        ),
    ]
