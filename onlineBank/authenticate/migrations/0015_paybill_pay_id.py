# Generated by Django 2.1.3 on 2018-12-22 00:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authenticate', '0014_paybill'),
    ]

    operations = [
        migrations.AddField(
            model_name='paybill',
            name='pay_id',
            field=models.CharField(default=0, max_length=5),
            preserve_default=False,
        ),
    ]
