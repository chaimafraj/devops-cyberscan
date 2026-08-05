from django.urls import path
from . import auth_views

urlpatterns = [
    path('login/', auth_views.login_view),
    path('register/', auth_views.register_view),
    path('me/', auth_views.me_view),
    path('logout/', auth_views.logout_view),
    path('users/', auth_views.users_list),
]