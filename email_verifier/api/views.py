from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .serializers import UserSerializer, EmailValidationSerializer
from .decorators import token_required  # Import the decorator
from .models import CreditToken

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailValidationView(APIView):
    @token_required
    def post(self, request):
        serializer = EmailValidationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({"message": "Valid email"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        
class GetTokenView(APIView):
    def get(self, request):
        user = request.user
        credit_token, created = CreditToken.objects.get_or_create(user=user)
        return Response({"token": credit_token.token, "balance": credit_token.balance})

