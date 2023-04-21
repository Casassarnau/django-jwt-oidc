from django import forms

from django_jwt.server.models import WebPage


class WebPageAdminForm(forms.ModelForm):
    class Meta:
        model = WebPage
        exclude = ()
        help_texts = {
            'host': 'Web page url without the last "/". Example: https://localhost:8000'
        }
