from django.contrib import admin

from django_jwt.server.forms import IdTokenExtraClaimAdminForm, RestrictUsersAdminForm, WebPageAdminForm
from django_jwt.server.models import WebPage, AttributeWebPage


class WebPagesAttributesAdmin(admin.StackedInline):
    verbose_name = 'ID Token extra claim'
    model = AttributeWebPage
    extra = 1
    form = IdTokenExtraClaimAdminForm

    def get_queryset(self, request):
        return super().get_queryset(request).filter(restrict=False)


class RestrictUsersAdmin(admin.StackedInline):
    verbose_name = 'User attribute restricted'
    verbose_name_plural = 'User attributes restricted'
    model = AttributeWebPage
    extra = 1
    form = RestrictUsersAdminForm

    def get_queryset(self, request):
        return super().get_queryset(request).filter(restrict=True)


@admin.register(WebPage)
class WebPageFullAdmin(admin.ModelAdmin):
    readonly_fields = ('id',)
    inlines = [WebPagesAttributesAdmin, RestrictUsersAdmin]
    form = WebPageAdminForm
