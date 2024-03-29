# Generated by Django 4.0.8 on 2023-04-14 15:07

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('sessions', '0001_initial'),
        ('django_jwt_server', '0002_webpage_logout_all'),
    ]

    operations = [
        migrations.CreateModel(
            name='NonceUsed',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nonce', models.CharField(max_length=100)),
                ('issued_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='PrivateClaimsWebPage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('attribute_from_user_model', models.CharField(help_text='You can use methods without "()" and use "." to get an attribute inside another one.', max_length=100)),
                ('claim', models.CharField(help_text='Claim name. Example: sub, etc.', max_length=100)),
                ('scope', models.CharField(help_text='Extra claim to warn user about what data is being used. Ex: email, profile, etc.', max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='RestrictUsersToWeb',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('attribute_from_user_model', models.CharField(help_text='You can use methods without "()" and use "." to get an attribute inside another one.', max_length=100)),
                ('value', models.CharField(help_text="If the user has the same value as this, it won't log in into this web page.", max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='WebAllowanceOtherWeb',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
        ),
        migrations.RenameField(
            model_name='userexternalsession',
            old_name='extra_id',
            new_name='access_token_id',
        ),
        migrations.RemoveField(
            model_name='webpage',
            name='needs_confirmation',
        ),
        migrations.RemoveField(
            model_name='webpage',
            name='response_type',
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='access_token_sent',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='authorization_code',
            field=models.CharField(blank=True, max_length=40),
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='code_challenge',
            field=models.TextField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='creation_date',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='id_token_sent',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='nonce',
            field=models.TextField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='refresh_token',
            field=models.IntegerField(default=1),
        ),
        migrations.AddField(
            model_name='userexternalsession',
            name='scopes',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='userwebpagepermission',
            name='scopes_json',
            field=models.TextField(default='[]'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='webpage',
            name='client_secret',
            field=models.CharField(default=uuid.uuid4, editable=False, max_length=40),
        ),
        migrations.AddField(
            model_name='webpage',
            name='logo',
            field=models.ImageField(blank=True, upload_to='django_jwt_oidc'),
        ),
        migrations.AddField(
            model_name='webpage',
            name='name',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='key',
            name='date',
            field=models.DateTimeField(default=django.utils.timezone.now, editable=False),
        ),
        migrations.AlterUniqueTogether(
            name='userexternalsession',
            unique_together={('session', 'web')},
        ),
        migrations.DeleteModel(
            name='AttributeWebPage',
        ),
        migrations.AddField(
            model_name='weballowanceotherweb',
            name='allowed_to',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='allowed_on', to='django_jwt_server.webpage'),
        ),
        migrations.AddField(
            model_name='weballowanceotherweb',
            name='web',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='django_jwt_server.webpage'),
        ),
        migrations.AddField(
            model_name='restrictuserstoweb',
            name='web',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='django_jwt_server.webpage'),
        ),
        migrations.AddField(
            model_name='privateclaimswebpage',
            name='web',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='django_jwt_server.webpage'),
        ),
        migrations.RemoveField(
            model_name='userexternalsession',
            name='date',
        ),
    ]
