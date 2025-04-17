from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('otp-verification/', views.otp_verification, name='otp_verification'),
    path('home/', views.home, name='home'),
    path('profile/', views.profile, name='profile'),
    path('settings/', views.setting, name='settings'),
    path('news/', views.news, name='news'),
    path('register/', views.register_view, name='register'),
    path('verify-otp/',views.verify_registration_otp, name='verify_registration_otp'),
    path('user-guide/', views.user_guide_view, name='user_guide'),

]