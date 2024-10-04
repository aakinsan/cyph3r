# Generated by Django 5.1.1 on 2024-10-03 22:58

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('cyph3r', '0006_delete_fileencryption_remove_keysplit_key_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='FileEncryption',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('encryption_algorithm', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='KeyGeneration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key_id', models.CharField(max_length=255)),
                ('date_generated', models.DateTimeField(auto_now_add=True)),
                ('key_size', models.IntegerField()),
                ('is_split', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='KeySplit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('number_of_shares', models.IntegerField()),
                ('type', models.CharField(choices=[('XOR', 'xor'), ('SHAMIR', 'shamir')], max_length=10)),
                ('key', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='cyph3r.keygeneration')),
            ],
        ),
    ]
