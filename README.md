# Django jwt
Django library that implements the authentification for OpenID Connect with JWT.
This authentification is compatible with django session workflow and the RestFramework library.

## Installation

- Install the library with pip
```bash
pip install django-jwt-oidc
```

- Add the `django_jwt` package into your `INSTALLED_APPS` in your settings.py file
```python
INSTALLED_APPS = [
    ...
    'django_jwt',
    ...
]
```

- Add django-jwt-oidc urls to your urls.py. You can change the path to the one you prefer.
```python
urlpatterns = [
    ...
    path('openid/', include('django_jwt.urls')),
    ...
]
```

<details>
<summary><h2>Set up client</h2></summary>
<br>

The `django-jwt-oidc` is a library that allows to implement a OIDC client in order to identify a user from a provider.

<details>
<summary><h3>Middleware</h3></summary>
<br>

- Add `JWTAuthenticationMiddleware` into your middleware after `SessionMiddleware`. You can optionally remove the `AuthenticationMiddleware` if you are not using other ways to log in.
```python
MIDDLEWARE = [
    ...
    'django.contrib.sessions.middleware.SessionMiddleware',
    ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_jwt.middleware.JWTAuthenticationMiddleware',
    ...
]
```
- If you removed the `AuthenticationMiddleware`, you will need to add this settings:
```python
SILENCED_SYSTEM_CHECKS = ['admin.E408']
```
- Set the django setting `LOGOUT_REDIRECT_URL` in order to redirect after logout.
- Add redirects to the `oidc_login` and `oidc_logout`. To make it default you can set `LOGIN_URL = 'oidc_login'`. 

#### Usage

- Getting authenticated user from request: `request.user`.
- Getting the ID token claims from the user: `request.user_claims`.
- Getting the userinfo from the endpoint from the user: `request.userinfo`.
- Getting a valid access token from the user: `request.get_access_token()`.

</details>

<details>
<summary><h3>RestFramework [Optional]</h3></summary>
<br>
This settings are for views inherits RestFramework library from Django.

- **You will need to [install RestFramework](https://www.django-rest-framework.org/#installation) on your own to your app first**

#### View setting
You can add this to your APIviews class by adding `JWTTokenAuthentication` to `authentification_classes` attribute.
In this example, the view requires that all requests must have ID Token JWT Bearer Authentication.

```python
from rest_framework import permissions, views
from django_jwt import JWTTokenAuthentication


class ExampleAPIView(view.APIView):
    authentication_classes = [JWTTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
```
#### Global setting
If all your application can work with JWT Bearer Authentication you can add the `JWTTokenAuthentication` class to `DEFAULT_AUTHENTICATION_CLASSES` setting on settings.py of your app.

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'django_jwt.rest_framework.JWTTokenAuthentication',
    ]
}
```

</details>

<details>
<summary><h3>Settings</h3></summary>
<br>

### Settings

All settings from the `django-jwt-oidc` library will be set inside a `JWT_OIDC` dictionary on `settings.py`.
```python
JWT_OIDC = {
    ...
}
```

#### TYPE [Required]
Set this to `client`.
```python
JWT_OIDC = {
    ...
    'TYPE': 'client',
    ...
}
```

#### DISCOVERY_ENDPOINT [Required]
Set this to the discovery endpoint of the provider.
```python
JWT_OIDC = {
    ...
    'DISCOVERY_ENDPOINT': 'https://domain/.well-known/openid-configuration',
    ...
}
```

#### CLIENT_ID [Required]
Set this to the client ID of your application in the provider.
```python
JWT_OIDC = {
    ...
    'CLIENT_ID': 'some_string',
    ...
}
```

#### RESPONSE_TYPE [Required]
Set this to the response type of your application in the provider. This determines the flow of your authentication.
```python
JWT_OIDC = {
    ...
    'RESPONSE_TYPE': 'code',  # Recommended to use Authorization Code flow
    ...
}
```

#### CLIENT_SECRET
Set this to the client secret of your application in the provider. This setting is required if want to Hybrid flow or Authorization Code flow (Setting `code` inside the `RESPONSE_TYPE`)
```python
JWT_OIDC = {
    ...
    'CLIENT_SECRET': 'some_string',
    ...
}
```

#### SCOPE
Set this to set the scope of the authentication flow.
```python
JWT_OIDC = {
    ...
    'SCOPE': 'openid',  # Default
    ...
}
```

#### IDENTIFICATION_CLAIM
Set this if you want to use some other claim as identifier for your user model. Default: `'sub'`
```python
JWT_OIDC = {
    ...
    'IDENTIFICATION_CLAIM': 'sub',  # default
    ...
}
```

#### ID_TOKEN_RENAME_ATTRIBUTES
Set this to change the claims names to be translated to your User model fields. `{'claim_name': 'model_field_name'}`
```python
JWT_OIDC = {
    ...
    'ID_TOKEN_RENAME_ATTRIBUTES': {},  # Default
    ...
}
```

#### CREATE_USER
Set this to `True` if you want to create users that they not exist.
```python
JWT_OIDC = {
    ...
    'CREATE_USER': False,  # Default
    ...
}
```


#### USER_DEFAULT_ATTRIBUTES
Set this to set defaults values to users that log in with the OIDC.
```python
JWT_OIDC = {
    ...
    'USER_DEFAULT_ATTRIBUTES': {},  # Default
    ...
}
```

#### PKCE_EXTENSION
Set this to activate the PKCE_EXTENSION. It is recommended.
```python
JWT_OIDC = {
    ...
    'PKCE_EXTENSION': False,  # Default
    ...
}
```

#### CODE_CHALLENGE_METHOD
Set this for the PKCE_EXTENSION method. Only `'S256'` supported.
```python
JWT_OIDC = {
    ...
    'CODE_CHALLENGE_METHOD': 'S256',  # Default
    ...
}
```

#### CLIENT_DISPLAY
Setting display for the authentication flow. Options: page, popup, touch and wap.
```python
JWT_OIDC = {
    ...
    'CLIENT_DISPLAY': '',  # Default
    ...
}
```

#### CLIENT_PROMPT
Setting prompt for the authentication flow. Options: login, consent, select_account and none.
```python
JWT_OIDC = {
    ...
    'CLIENT_PROMPT': '',  # Default
    ...
}
```

#### CLIENT_MAX_AGE
Setting max_age for the authentication flow. How many seconds the user has logged in the provider.
```python
JWT_OIDC = {
    ...
    'CLIENT_PROMPT': '',  # Default
    ...
}
```

#### OTHER
Other settings for the authentication flow.

 - CLIENT_UI_LOCALES
 - CLIENT_CLAIMS_LOCALES
 - CLIENT_ID_TOKEN_HINT
 - CLIENT_LOGIN_HINT
 - CLIENT_ACR_VALUES

</details>

</details>

<details>
<summary><h2>Set up provider</h2></summary>
<br>

This is an extra app of the django_jwt app that deploys a OpenID Connect provider with implicit flow (Not recommended), Hybrid flow, Authorization Code flow and Authorization Code flow with PKCE.
The JWTs are signed by RSA or ECC keys that are being regenerated to improve security.<br>
**Django JWT Server does not provide for a login view.**

### Installation

- Install [django-cors-headers](https://pypi.org/project/django-cors-headers/) library into your app. Required in order to control the CORS policy from your apps. **There is no need to add the domains one by one**
- Install [djangorestframework](https://www.django-rest-framework.org/#installation) library into your app.
- Add `django_jwt.server` to your installed apps.
- Migrate the database with `python manage.py migrate`.
- Add your implemented Django log in into `LOGIN_URL` setting on `settings.py`.
- Run your app in order to set up your hosts into the admin page.

<details>
<summary><h3>Settings</h3></summary>
<br>

All settings from the `django-jwt-oidc` library will be set inside a `JWT_OIDC` dictionary on `settings.py`.
```python
JWT_OIDC = {
    ...
}
```

#### TYPE [Required]
Set this to `provider`.
```python
JWT_OIDC = {
    ...
    'TYPE': 'provider',
    ...
}
```

#### DISCOVERY_ENDPOINT [Required]
Set this to your discovery endpoint of the provider.
```python
JWT_OIDC = {
    ...
    'DISCOVERY_ENDPOINT': 'https://my-domain/.well-known/openid-configuration',
    ...
}
```

#### SIGNATURE_ALG
Set this to the algorithm used to sign tokens. ECC is recommended.
```python
JWT_OIDC = {
    ...
    'SIGNATURE_ALG': 'ES512',  # Default
    ...
}
```

#### JWK_EXPIRATION_TIME
Expiration time (in seconds) of the RSA or ECC keys. They will be stopped to be used for **signing** after this time.
They will be deleted after not needed again for validation.
```python
JWT_OIDC = {
    ...
    'JWK_EXPIRATION_TIME': 3600,  # Default
    ...
}
```

#### JWT_ID_TOKEN_EXPIRATION_TIME
Expiration time (in seconds) of the ID tokens.
```python
JWT_OIDC = {
    ...
    'JWT_ID_TOKEN_EXPIRATION_TIME': 2700,  # Default
    ...
}
```

#### JWT_ACCESS_TOKEN_EXPIRATION_TIME
Expiration time (in seconds) of the access tokens. Recommended to be low.
```python
JWT_OIDC = {
    ...
    'JWT_ACCESS_TOKEN_EXPIRATION_TIME': 600,  # Default
    ...
}
```

#### JWT_REFRESH_TOKEN_EXPIRATION_TIME
Expiration time (in seconds) of the refresh tokens. Must be higher than access tokens.
```python
JWT_OIDC = {
    ...
    'JWT_ACCESS_TOKEN_EXPIRATION_TIME': 3600,  # Default
    ...
}
```

#### MAX_REFRESH
Set this in order to only be able to refresh tokens x times.
```python
JWT_OIDC = {
    ...
    'MAX_REFRESH': 10,  # Default
    ...
}
```

#### USERINFO_SERIALIZER
User model serializer.
```python
JWT_OIDC = {
    ...
    'USERINFO_SERIALIZER': 'django_jwt.server.serializers.UserSerializer',  # Default
    ...
}
```

#### USERINFO_SERIALIZER_EXCLUDE
Exclude fields of the User model in the `'django_jwt.server.serializers.UserSerializer'`.
```python
JWT_OIDC = {
    ...
    'USERINFO_SERIALIZER_EXCLUDE': ['password'],  # Default
    ...
}
```

</details>

</details>

<details>
<summary><h2>Set up fake server for deployment</h2></summary>
<br>

This is an extra functionality of the `django_jwt` app that makes a OpenId server with oauth 2.0 with implicit flow with an input to "log in" as whatever sub value you want. 

**Not maintained to changes of the 1.0 version.**

### Installation

- Install [django-cors-headers](https://pypi.org/project/django-cors-headers/) library into your app. Required in order to control the CORS policy from your frontend.
- Add your frontend domain into `CORS_ALLOWED_ORIGINS`.
- Change the `JWT_OIDC['TYPE']` setting to `'fake'`.
- Set up the `JWT_OIDC['CLIENT_ID']` setting to the same client id your frontend is targeting.
- Set up the `DEFAULT_DOMAIN` setting on your Django settings. Example:
```python
DEFAULT_DOMAIN = 'https://localhost:8000'
```
- Set up your frontend url into the path that you included in `urls.py`.

</details>

<style>
details summary > * {  
    display: inline; 
}
details {
    margin-top: 25px;
}
</style>
