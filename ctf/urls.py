from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    url(r'^handlers/', include(admin.site.urls)),
    url(r'^', include('members.urls',namespace="agents")),
]
