# Generated by Django 2.1.3 on 2018-12-12 06:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usersModule', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='bills',
            name='bill_type',
            field=models.CharField(default='transfer', max_length=8),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='bills',
            name='amount',
            field=models.FloatField(),
        ),
    ]