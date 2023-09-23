from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, AddressViewSet
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm

router = DefaultRouter()
router.register(r'user', UserViewSet)
router.register(r'user/addresses', AddressViewSet, basename='user-address')

app_name = 'backend'
urlpatterns = [
    path('user/password_reset/', reset_password_request_token, name='password-reset'),
    path('user/password_reset/confirm/', reset_password_confirm, name='password-reset-confirm'),
] + router.urls
