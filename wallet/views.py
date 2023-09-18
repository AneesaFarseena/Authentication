from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import UserRegister, EmailSerializer, ResetPasswordSerializer
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, status, viewsets
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse

class register(APIView):

    def post(self,request,format=None):
        serializer = UserRegister(data=request.data)
        data = {}
        if serializer.is_valid():
            account = serializer.save()
            data['response'] = 'registered'
            data['username'] = account.username
            data['email'] = account.email
            token,create = Token.objects.get_or_create(user=account)          
            data['token'] = token.key
        else:
            data = serializer.errors
        return Response(data) 
    
class welcome(APIView):
    permission_classes = (IsAuthenticated,)    

    def get(self, request):
        content = {'user':str(request.user),'user_id':str(request.user.id)}
        return Response(content)
    
class PasswordReset(generics.GenericAPIView):

    serializer_class = EmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        user = User.objects.filter(email=email).first()
        if user:
            encoded_pk  = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)

            # localhost:8000/reset-password/<encoded_pk>/<token>/ 

            reset_url = reverse("reset-password", kwargs={"encoded_pk":encoded_pk, "token":token})

            reset_url = f"localhost:8000{reset_url}"

            return Response({"message":f"Your password reset link: {reset_url}"},
                            status=status.HTTP_200_OK,)
        
        else:
            return Response({"message":"User doesn't exists"},
                            status=status.HTTP_400_BAD_REQUEST,)
        

class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def patch(self, request, *args, **kwargs ):
        serializer = self.serializer_class(data=request.data, context={"kwargs":kwargs})

        serializer.is_valid(raise_exception=True)

        return Response({"message":"Password reset complete"},
                        status=status.HTTP_200_OK,)
    
     
                
    

    
