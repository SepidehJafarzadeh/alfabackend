from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.hashers import check_password
from accounts.models import User


class LoginUsingUsernameBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        if check_password(password, user.password):
            return user
        return None


class LoginUsingEmailBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return None

        if check_password(password, user.password):
            return user
        return None
    

