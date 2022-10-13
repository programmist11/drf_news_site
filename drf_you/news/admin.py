from django.contrib import admin
from .models import  News, Category, Ip, Account,Review

admin.site.register(News)
admin.site.register(Category)
admin.site.register(Account)
admin.site.register(Review)
