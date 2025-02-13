# Generated by Django 5.1.6 on 2025-02-13 09:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='bio',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('SA', 'Super Admin'), ('AD', 'Admin'), ('AI', 'AI Assistant')], default='AD', max_length=2),
        ),
        migrations.AlterField(
            model_name='user',
            name='image',
            field=models.ImageField(default='users/avatar.png', upload_to='users/'),
        ),
    ]
