from django.db import models
import secrets
from django.db import models
from django.contrib.auth.models import User

class CreditToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True, default=secrets.token_hex)
    balance = models.IntegerField(default=10)  # Default credits

    def __str__(self):
        return f"{self.user.username} - {self.balance} credits"
