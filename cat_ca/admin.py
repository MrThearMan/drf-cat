from django.contrib import admin

from cat_ca.models import ServiceEntity, ServiceEntityType


@admin.register(ServiceEntity)
class ServiceEntityAdmin(admin.ModelAdmin):
    pass


@admin.register(ServiceEntityType)
class ServiceEntityTypeAdmin(admin.ModelAdmin):
    pass
