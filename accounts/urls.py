from django.urls import path
from accounts import views

urlpatterns = [
    path('', views.home, name='home'),
    path("send-otp/", views.send_otp, name="send-otp"),
    path("verify-email/", views.verify_email, name="verify-email"),
    path("register/", views.register_user, name="register"),
    path("login/", views.login_user, name="login"),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('send-reset-link/', views.send_reset_link, name='send_reset_link'),
    path("reset-password/<uidb64>/<token>/", views.reset_password_view, name="reset_password"),
    path("update-password/", views.update_password, name="update_password"), 
    path('logout/', views.userlogout, name='userlogout'),
]
