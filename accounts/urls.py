from django.urls import path
from .views import LoginView, RegisterView , GoogleAuthView, GoogleAuthCallbackView

app_name = 'accounts'
urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('google/', GoogleAuthView.as_view(), name='google'),
    path('callback/', GoogleAuthCallbackView.as_view(), name='callback'),
]