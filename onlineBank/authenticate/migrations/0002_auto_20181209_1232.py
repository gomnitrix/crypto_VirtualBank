# Generated by Django 2.1.3 on 2018-12-09 04:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authenticate', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='cost',
            field=models.PositiveIntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='user',
            name='pay_passwd',
            field=models.PositiveIntegerField(default=12345678, max_length=8),
            preserve_default=False,
        ),
    ]
