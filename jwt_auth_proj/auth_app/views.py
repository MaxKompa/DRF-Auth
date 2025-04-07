from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from .authentication import generate_access_token, generate_refresh_token, JWTAuthentication
import jwt
from django.conf import settings


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if not user:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        return Response({
            'access_token': access_token,
            'refresh_token': refresh_token
        })


class RefreshTokenView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny] 

    def post(self, request):
        old_token = request.data.get('token')

        if not old_token:
            raise AuthenticationFailed("Token is required")

        try:
            payload = jwt.decode(
                old_token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                options={'verify_exp': False}  
            )
            user = User.objects.get(id=payload['user_id'])
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')

        new_token = generate_access_token(user)
        return Response({'token': new_token})




class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_authenticated:
            return Response({'message': f'Hello, {request.user.username}!'})
        else:
            return Response({'error': 'User not authenticated'}, status=403)
