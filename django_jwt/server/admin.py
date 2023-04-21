from django.contrib import admin

from django_jwt.server.forms import WebPageAdminForm
from django_jwt.server.models import WebPage, PrivateClaimsWebPage, RestrictUsersToWeb, WebAllowanceOtherWeb


class PrivateClaimsWebPageAdmin(admin.StackedInline):
    verbose_name = 'ID Token extra claim'
    model = PrivateClaimsWebPage
    extra = 1


class RestrictUsersToWebAdmin(admin.StackedInline):
    verbose_name = 'User attribute restricted'
    verbose_name_plural = 'User attributes restricted'
    model = RestrictUsersToWeb
    extra = 1


class WebAllowanceOtherWebAdmin(admin.StackedInline):
    verbose_name = 'Allow 3rd party web'
    model = WebAllowanceOtherWeb
    extra = 1
    fk_name = 'web'


@admin.register(WebPage)
class WebPageFullAdmin(admin.ModelAdmin):
    readonly_fields = ('id', 'client_secret')
    inlines = [PrivateClaimsWebPageAdmin, RestrictUsersToWebAdmin, WebAllowanceOtherWebAdmin]
    form = WebPageAdminForm
