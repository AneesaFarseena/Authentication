from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode


User= get_user_model()


class UserRegister(serializers.ModelSerializer):

    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'password2']

    def save(self):
        reg = User(
            email = self.validated_data['email'],
            username = self.validated_data['username'],
            

        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password':'password does not match'})
        reg.set_password(password)   
        reg.save()
        return reg
    
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()    

    class Meta:
        model = User
        fields = ['email']


class ResetPasswordSerializer(serializers.Serializer):

    password = serializers.CharField(write_only=True,min_length=4,)

    class Meta:
        fields = ['password']   

    def validate(self, data):
        password = data.get("password")
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")      

        if token is None or encoded_pk  is None:  
            serializers.ValidationError("Missing data")

        pk = urlsafe_base64_decode(encoded_pk).decode()   
        user=User.objects.get(pk=pk) 

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("The token is invalid")
        user.set_password(password)
        user.save()
        return data
    