from django.contrib import admin
from .models import User, Account, PayBill

# Register your models here.
admin.site.register(User)
admin.site.register(Account)
admin.site.register(PayBill)


class Admin(admin.ModelAdmin):
    readonly_fields = ('regtime',)
