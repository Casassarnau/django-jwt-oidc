# Django jwt
Django library that implements the authentification for OpenId SSO with JWT from oauth2.
This authentification is compatible with django session workflow and the RestFramework library.

## Installation

Install the library with pip
```bash
pip install django-jwt-oidc
```

Add the `django_jwt` package into your `INSTALLED_APPS` in your settings.py file
```python
INSTALLED_APPS = [
    ...
    'django_jwt',
    ...
]
```

## Django [WIP]
This is what you need to do in order that your Django application will authenticate with JWT.
 
- Add `django_jwt.urls` to your app urls.
- Add `JWTAuthenticationMiddleware` into your middleware after `AuthenticationMiddleware`.
```python
MIDDLEWARE = [
    ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_jwt.middleware.JWTAuthenticationMiddleware',
    ...
]
```
- Set the `RESPONSE_TYPE` setting into your `JWT_CLIENT` setting to `id_token`.
```python
JWT_CLIENT = {
    ...
    'RESPONSE_TYPE': 'id_token',
}
```
- Set the django setting `LOGOUT_REDIRECT_URL` in order to redirect after logout.

## RestFramework
This settings are for views inherits RestFramework library from Django.
**You will need to install RestFramework on your own to your app first**

### View setting
You can add this to your APIviews class by adding `JWTTokenAuthentication` to `authentification_classes` attribute.
In this example, the view requires that all requests must have JWT Bearer Authentication.

```python
from rest_framework import permissions, views
from django_jwt import JWTTokenAuthentication


class ExampleAPIView(view.APIView):
    authentication_classes = [JWTTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
```
### Global setting
If all your application can work with JWT Bearer Authentication you can add the `JWTTokenAuthentication` class to `DEFAULT_AUTHENTICATION_CLASSES` setting on settings.py of your app.

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'django_jwt.rest_framework.JWTTokenAuthentication',
    ]
}
```
## Fake server (deployment only)
This is an extra functionality of the `django_jwt` app that makes a OpenId server with oauth 2.0 with implicit flow with an input to "log in" as whatever sub value you want. 

### Installation

- Install [django-cors-headers](https://pypi.org/project/django-cors-headers/) library into your app. Required in order to control the CORS policy from your frontend.
- Add your frontend domain into `CORS_ALLOWED_ORIGINS`.
- Change the [CLIENT_JWT \[ OPENID2_URL \]](#openid2_url--jwt_client-) setting to `'fake'`.
- Set up the [CLIENT_JWT \[ CLIENT_ID \]](#client_id--jwt_client-) setting to the same client id your frontend is targeting.
- Include the `django_jwt.urls` into your `urls.py`.
- Set up the `DEFAULT_DOMAIN` setting on your Django settings. Example:
```python
DEFAULT_DOMAIN = 'https://localhost:8000'
```
- Set up your frontend url into the path that you included in `urls.py`.

## Server
This is an extra app of the django_jwt app that deploys a OpenId server with oauth 2.0 with implicit flow (more coming soon).
The JWTs are signed by a RS256 algorithm that regenerates the rsa private keys.
Access tokens expire after 1 hour kept by the Implicit Flow protocol. <br>
**Django JWT Server does not provide for a login view.**

### Installation
- Install [django-cors-headers](https://pypi.org/project/django-cors-headers/) library into your app. Required in order to control the CORS policy from your apps. **There is no need to add the domains one by one**
- Add `django_jwt.server` to your installed apps.
- Change the [CLIENT_JWT \[ OPENID2_URL \]](#openid2_url--jwt_client-) setting to `'local'`.
- Migrate the database with `python manage.py migrate`.
- Add your implemented Django log in into `LOGIN_URL` setting on `settings.py`.
- Run your app in order to set up your hosts into the WebPage model.
- (Optional) If you want to use your id_tokens in your app, set up the [CLIENT_JWT \[ CLIENT_ID \]](#client_id--jwt_client-) setting to the same client id that you just created.

## Settings
The settings are separated into 2 main Django settings `JWT_CLIENT` for the `django_jwt` app and `JWT_SERVER` for the `django_jwt.server` app.

### OPENID2_URL [ JWT_CLIENT ]
The openid service url without the `/.well-known/openid-configuration` path.

### CLIENT_ID [ JWT_CLIENT ]
This is the client id of the openId service you are using. <br>
If you want to validate the jwt from the OpenId server by `django_jwt.server` app you will need to add here the generated client_id on the admin page.

### TYPE [ JWT_CLIENT ]
This has 3 settings: `remote`, `local` and `fake` in order to use any of these types.

### RENAME_ATTRIBUTES [ JWT_CLIENT ]
Dictionary to redirect the data and the `sub` attribute into the User attributes.

### CREATE_USER [ JWT_CLIENT ]
Boolean that creates a Django user by default if the user doesn't exists if set to `False`.

### DEFAULT_ATTRIBUTES [ JWT_CLIENT ]
Dictionary that sets default values to new Users created.
This example sets the all the attibutes of users created by the library `auto_created` to `True`.

### COOKIE_NAME [ JWT_CLIENT ]
String that represents the identification of the cookie id of the JWT.

### Example of JWT_CLIENT on settings.py

```python
JWT_CLIENT = {
    'OPENID2_URL': 'https://localhost:8000',    # Required
    'CLIENT_ID': 'client_id',                   # Required
    'TYPE': 'remote',                           # Required
    'RENAME_ATTRIBUTES': {'sub': 'username'},   # Optional
    'DEFAULT_ATTRIBUTES': {},                   # Optional
    'CREATE_USER': True,                        # optional
    'COOKIE_NAME': 'id_token'                   # Optional
}
```

### JWT_EXPIRATION_TIME [ JWT_SERVER ]
This setting is to change the expiration time (in seconds) for JWT generated by the server. This not includes the fake server.

### JWK_EXPIRATION_TIME [ JWT_SERVER ]
This setting is to change the expiration time (in seconds) for the JWK generated by the server. This must be grater than `JWT_EXPIRATION_TIME` 

### Example of JWT_SERVER on settings.py

```python
JWT_SERVER = {
    'JWK_EXPIRATION_TIME': 3600,                # Optional
    'JWT_EXPIRATION_TIME': 14400                # Optional
}
```

### Changing the values of the jwt
You can also modify attributes like adding something to the value creating a change_[attribute_name] method on the User model.<br>
Example of changing the username attribute:

```python
class User(AbstractBaseUser):
    def change_username(self, value):
        return value + '@jwt'
```

### Changing the default creation of the user
You can also change the creation method of the BaseUserManager of the AbstractBaseUser model in order to customize its default creation.

```python
class UserManager(BaseUserManager):
    def get_or_create(self, defaults=None, **kwargs):
        ...

class User(AbstractBaseUser):
    objects = UserManager()
    ...
```
