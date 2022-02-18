# django-jwt-oidc
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

## Settings
### JWT_OPENID2_URL
The openid service url without the `/.well-known/openid-configuration` path.
```python
JWT_OPENID2_URL = 'https://localhost:8000'
```
**Developing only:** If this setting is set to `'fake'`, it will deploy a fake openid service, you will need to inlcude the `'django_jwt.urls'` on your urls.py and also set `DEFAULT_DOMAIN` to your app domain.

### JWT_RENAME_ATTRIBUTES
Dictionary to redirect the data and the `sub` attribute into the User attributes.

```python
JWT_RENAME_ATTRIBUTES = {'sub': 'username'}
```

### JWT_CREATE_USER
Boolean that creates a Django user by default if the user doesn't exists if set to `True`.

```python
JWT_CREATE_USER = True
```

You can also change the creation method of the QuerysetManager of the User model in order to customize this.
```python
class UserQueryset(QuerySet):
    def get_or_create(self, defaults=None, **kwargs):
        ...

class User(AbstractBaseUser):
    objects = UserQueryset.as_manager()
    ...
    
```

### JWT_DEFAULT_ATTRIBUTES
Dictionary that sets default values to new Users created.
This example sets the all the attibutes of users created by the library `auto_created` to `True`.

```python
JWT_DEFAULT_ATTRIBUTES = {'auto_created': True}
```

You can also modify attributes like adding something to the value creating a change_[attribute_name] method on the User model.
```python
class User(AbstractBaseUser):
    def change_username(self, value):
        return value + '@jwt'
```
