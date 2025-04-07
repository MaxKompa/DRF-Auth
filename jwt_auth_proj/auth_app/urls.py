from django.urls import path
from .views import LoginView, RefreshTokenView, ProtectedView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
]
