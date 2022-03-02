# Generated by Django 4.0 on 2022-02-22 11:05

import datetime
from django.db import migrations, models
import django.db.models.deletion
import django_jwt.server.models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Key',
            fields=[
                ('kid', models.CharField(default=uuid.uuid4, editable=False, max_length=40, primary_key=True, serialize=False)),
                ('private_key', models.BinaryField(default=django_jwt.server.models.generate_key)),
                ('date', models.DateTimeField(default=datetime.datetime.now, editable=False)),
            ],
        ),
        migrations.CreateModel(
            name='WebPage',
            fields=[
                ('id', models.CharField(default=uuid.uuid4, editable=False, max_length=40, primary_key=True, serialize=False, verbose_name='Client id')),
                ('host', models.CharField(max_length=200, unique=True)),
                ('needs_confirmation', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='UserWebPagePermission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.user')),
                ('web', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='server.webpage')),
            ],
        ),
        migrations.CreateModel(
            name='UserExternalSession',
            fields=[
                ('id', models.CharField(default=uuid.uuid4, editable=False, max_length=40, primary_key=True, serialize=False)),
                ('extra_id', models.CharField(default=uuid.uuid4, max_length=40, unique=True)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='sessions.session')),
                ('web', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='server.webpage')),
            ],
        ),
        migrations.CreateModel(
            name='AttributeWebPage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('attribute', models.CharField(max_length=100)),
                ('value', models.CharField(max_length=100)),
                ('restrict', models.BooleanField(default=False)),
                ('web', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='server.webpage')),
            ],
        ),
    ]
