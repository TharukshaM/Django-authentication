from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken

class USER(AbstractUser):
    username = models.CharField(max_length=100, null=True, blank=True, unique=True)
    email = models.EmailField(max_length=100, unique=True, db_index=True)
    fullname = models.CharField(max_length=100, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    GENDER_CHOICES = [('M', 'Male'), ('F', 'Female'), ('O', 'Other')]
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)
    is_authorized = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.username
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }