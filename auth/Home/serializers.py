from rest_framework import serializers
from .models import USER
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.crypto import get_random_string

class REGISTERSERIALIZER(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100)
    is_superuser = serializers.BooleanField(default=False)
    is_staff = serializers.BooleanField(default=False)

    class Meta:
        model = USER
        fields = ('username','fullname','date_of_birth','gender','email', 'password', 'is_superuser', 'is_staff')
    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username','')
        if not username.isalnum():
            raise serializers.ValidationError('The username should be alphanumeric')
        return attrs
    
    def create(self, validated_data):
        user = USER.objects.create_user(
            username = validated_data['username'],
            email = validated_data['email'],
            password = validated_data['password'],
            fullname = validated_data['fullname'],
            date_of_birth = validated_data['date_of_birth'],
            gender = validated_data['gender'],
            is_superuser = validated_data['is_superuser'],
            is_staff = validated_data['is_staff']
        )
        # Use set password method to hash the password 
        user.set_password(validated_data['password'])
        user.save()
        return user
class LOGINSERIALIZER(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3)
    tokens = serializers.SerializerMethodField()
    def get_tokens(self, obj):
        user = USER.objects.get(username=obj['username'])
        return user.tokens
    class Meta:
        model = USER
        fields = ['username', 'password', 'tokens']
    def validate(self,attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')

    # Check if the user exists 
    if not USER.objects.filter(username=username).exists():
        raise AuthenticationFailed('Invalied username, try again !')
    user = auth.authenticate(username=username,password=password)
    
    #Check if the password is correct
    if user is None:
        raise AuthenticationFailed('Incorrect password, try again !')
    
    if not user.is_active:
        raise AuthenticationFailed('Account disabled, contact admin !')
    
    if not user.is_authorized:
        raise AuthenticationFailed('Account not authorized, contact admin !')
    
    return {
        'email': user.email,
        'username': user.username,
        'tokens': user.tokens()
    }

class LOGOUTSERIALIZER(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError as e:
            raise serializers.ValidationError(str(e))

class PASSWORDRESETSERIALIZER(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = USER.objects.filter(email=value).first()
        if user is None:
            raise serializers.ValidationError('User not found')
        return value

    def save(self):
        email = self.validated_data['email']
        user = USER.objects.get(email=email)

        otp = get_random_string(length=6, allowed_chars='0123456789')
        user.login_token = otp
        user.save()
        return {'user': user, 'otp': otp}