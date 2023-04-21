from django import forms

from django_jwt.server.models import WebPage


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
