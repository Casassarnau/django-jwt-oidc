from django import forms

from django_jwt.server.models import AttributeWebPage, WebPage


class IdTokenExtraClaimAdminForm(forms.ModelForm):
    restrict = forms.BooleanField(widget=forms.HiddenInput(), initial=False, required=False)

    class Meta:
        model = AttributeWebPage
        exclude = ()
        labels = {
            'attribute': 'Claim name',
            'value': 'User attribute',
        }
        help_texts = {
            'value': 'You can use methods without "()" and use "." to get an attribute inside another one.'
        }


class RestrictUsersAdminForm(forms.ModelForm):
    restrict = forms.BooleanField(widget=forms.HiddenInput(), initial=True, required=False)

    class Meta:
        model = AttributeWebPage
        exclude = ()
        labels = {
            'attribute': 'User attribute',
        }
        help_texts = {
            'value': 'If the user has the same value as this, it won\'t log in into this web page.'
        }


class WebPageAdminForm(forms.ModelForm):
    class Meta:
        model = WebPage
        exclude = ()
        labels = {
            'logout_all': 'Log out from main page',
            'response_type': 'Log in response type'
        }
        help_texts = {
            'host': 'Web page url without the last "/". Example: https://localhost:8000',
            'response_type': 'Hash response is for frontend auth and Params for backend',
        }
