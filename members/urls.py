from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^agents/login/$', views.login, name='login'),
    url(r'^agents/logout/$', views.logout_page, name='logout'),
    url(r'^agents/register/$', views.register_page, name='register'),
    url(r'^agents/newsfeed/$', views.newsfeed, name='newsfeed'),
    url(r'^agents/topagents/$', views.topagents, name='topagents'),
    url(r'^agents/register/success/$', views.register_success,name='success'),
    url(r'^agents/contract/category/(?P<category_id>\d+)$', views.contract_categories,name='contract_categoires'),
    url(r'^agents/contract/category/$', views.all_contract_categories,name='contract_categoires'),
    url(r'^agents/contract/(?P<contract_id>\d+)$', views.contract,name='contract'),

    #{ 'template': 'registration/register_success.html' }),
    #(r'^site_media/(?P<path>.*)$', 'django.views.static.serve',
    #{ 'document_root': site_media }),
   # url(r'^(?P<poll_id>\d+)/$', views.detail, name='detail'),
   # url(r'^(?P<poll_id>\d+)/results/$', views.results, name='results'),
   # url(r'^(?P<poll_id>\d+)/vote/$', views.vote, name='vote'),
]
