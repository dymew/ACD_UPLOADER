# -*- coding: utf-8 -*-
# Generated by Django 1.10.4 on 2016-12-06 17:37
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('db', '0002_auto_20161205_1848'),
    ]

    operations = [
        migrations.AddField(
            model_name='entry',
            name='last_check_date',
            field=models.BigIntegerField(default=0),
        ),
    ]
