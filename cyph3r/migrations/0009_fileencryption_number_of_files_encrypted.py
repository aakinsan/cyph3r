# Generated by Django 5.1.1 on 2024-10-03 23:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cyph3r", "0008_fileencryption_key_alter_keysplit_key"),
    ]

    operations = [
        migrations.AddField(
            model_name="fileencryption",
            name="number_of_files_encrypted",
            field=models.IntegerField(default=0),
        ),
    ]
