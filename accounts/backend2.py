from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.create_user(username='username', password='password',
                                backend='django.contrib.auth.backends.ModelBackend')