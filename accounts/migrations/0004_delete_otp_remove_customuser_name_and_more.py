# Generated by Django 5.1.6 on 2025-04-09 06:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_otp'),
    ]

    operations = [
        migrations.DeleteModel(
            name='OTP',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='name',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='phone',
        ),
        migrations.AddField(
            model_name='customuser',
            name='email_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='customuser',
            name='otp',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='is_superuser',
            field=models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status'),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='password',
            field=models.CharField(max_length=128, verbose_name='password'),
        ),
    ]
