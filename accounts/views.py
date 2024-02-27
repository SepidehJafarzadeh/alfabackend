from django.shortcuts import render
from accounts.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login

from rest_framework_jwt.settings import api_settings
from alfabackend import settings
import requests
import random
import string
from django.utils.encoding import force_bytes
import json

# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')
            email = request.data.get('email')
            user = User.objects.create_user(username=username, password=password, email=email)
            if user is not None:
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                return Response({'message':'you have registered'}, status=status.HTTP_200_OK)
            else:
                return Response({'message':'you did not register'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message':str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            return Response({'message':'you have logged in'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':'you did not log in'}, status=status.HTTP_400_BAD_REQUEST)
        



class GoogleAuthView(APIView):
    def get(self, request):
        # Build the authorization URL
        base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
        redirect_uri = "http://127.0.0.1:8000/callback/"
        scope = 'email profile openid'
        state = 'random_state_value'  # Replace with your own random string
        auth_url = f"{base_url}?client_id={settings.GOOGLE_CLIENT_ID}&redirect_uri={redirect_uri}&response_type=code&scope={scope}&state={state}"

        # Return the authorization URL as a JSON response
        return Response({'auth_url': auth_url})


class GoogleAuthCallbackView(APIView):
    def get(self, request):
        # Get the authorization code from the request
        code = request.GET.get('code')

        # Exchange the authorization code for tokens
        token_url = 'https://oauth2.googleapis.com/token'
        redirect_uri = "http://127.0.0.1:8000/callback/"
        data = {
            'code': code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        }
        response = requests.post(token_url, data=data)

        if response.status_code == 400:
            return Response(data='Login failed', status=status.HTTP_401_UNAUTHORIZED)

        access_token = response.json()['access_token']
        # Now you have the access_token, you can use it to make requests to Google APIs
        # For example, to get user info:
        user_info_response = requests.get('https://openidconnect.googleapis.com/v1/userinfo',
                                          headers={'Authorization': f'Bearer {access_token}'})
        user_info = user_info_response.json()
        # Extract user's email from the response
        user_email = user_info.get('email')
        
        # Create a random password for the user
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        # Create a user using the email obtained from the Google API
        user = User.objects.create_user(username=user_email, password=password, email=user_email)

        # Log in the user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        # Generate a JWT token for the user
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler((payload))

        return Response(data={'token': token}, status=status.HTTP_200_OK)