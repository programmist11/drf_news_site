from django.contrib import admin

from .models import Account, Category, Ip, News, Review

admin.site.register(News)
admin.site.register(Category)
admin.site.register(Account)
admin.site.register(Review)
