from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('su_request/', views.su_request, name='su_request'),
    path('signin/', views.signin, name='signin'),
    path('prompt/', views.prompt, name="prompt"),
    path('setpay/<str:name>/', views.set_paypasswd, name="set_paypasswd"),
    path('pay/<int:pay_id>/', views.pay, name="pay"),
    path('deal/', views.deal, name="deal"),
    path('pay_transfer/<int:pay_id>/', views.pay_transfer, name="pay_transfer"),
    path('key/<str:name>', views.key, name="key"),
]
