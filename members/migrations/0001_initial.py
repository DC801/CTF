# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-07-10 23:29
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0007_alter_validators_add_error_messages'),
    ]

    operations = [
        migrations.CreateModel(
            name='MemberUser',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('email', models.CharField(db_index=True, max_length=254, unique=True)),
                ('handle', models.CharField(max_length=254, unique=True)),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('first_name', models.CharField(blank=True, max_length=254)),
                ('last_name', models.CharField(blank=True, max_length=254)),
                ('phone_number', models.CharField(blank=True, max_length=11)),
                ('confirmation_code', models.CharField(max_length=33)),
                ('secret_phrase', models.CharField(max_length=254)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
            },
        ),
        migrations.CreateModel(
            name='Capture',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('capture_date', models.DateTimeField(verbose_name=b'Date flags was captured.')),
                ('valid', models.BooleanField()),
                ('evidence_prehash', models.CharField(blank=True, max_length=254)),
                ('evidence_hash', models.CharField(blank=True, max_length=254)),
                ('evidence', models.TextField()),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ChallengeLevel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=254)),
            ],
        ),
        migrations.CreateModel(
            name='Contract',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=254)),
                ('file', models.CharField(blank=True, max_length=254)),
                ('description', models.CharField(max_length=254)),
                ('breifing', models.TextField()),
                ('flag_answer', models.CharField(max_length=254)),
                ('flag_prehash', models.CharField(blank=True, max_length=254)),
                ('flag_hash', models.CharField(blank=True, max_length=254)),
                ('payment', models.DecimalField(decimal_places=2, max_digits=8)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ContractCategory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=254)),
            ],
        ),
        migrations.CreateModel(
            name='CTFGame',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=254)),
                ('start_time', models.DateTimeField(verbose_name=b'Date Game Starts')),
                ('end_time', models.DateTimeField(verbose_name=b'Date Game Ends')),
                ('description', models.CharField(max_length=254)),
            ],
        ),
        migrations.CreateModel(
            name='NewsFeed',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('info', models.CharField(max_length=254)),
                ('publish_date', models.DateTimeField()),
                ('info_type', models.IntegerField()),
                ('game_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='members.CTFGame')),
            ],
        ),
        migrations.AddField(
            model_name='contractcategory',
            name='game_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='members.CTFGame'),
        ),
        migrations.AddField(
            model_name='contract',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='members.ContractCategory'),
        ),
        migrations.AddField(
            model_name='contract',
            name='challenge_level',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='members.ChallengeLevel'),
        ),
        migrations.AddField(
            model_name='contract',
            name='game_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='members.CTFGame'),
        ),
        migrations.AddField(
            model_name='contract',
            name='handler',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='capture',
            name='contract',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='members.Contract'),
        ),
        migrations.AddField(
            model_name='capture',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
