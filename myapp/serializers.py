from rest_framework import serializers
from django.core.mail import EmailMessage
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed

from myapp  import models
from myproject import settings

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils. encoding import force_bytes,force_text, DjangoUnicodeDecodeError

from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) +
            six.text_type(user.is_active)
        )

account_activation_token = TokenGenerator()

class UserSerializers(serializers.ModelSerializer):
	# token = serializers.CharField(max_length=100, null=True, blank=True)
	class Meta:
		model = models.User
		fields = ['id', 'userName', 'fullName','email', 'password']
		extra_kwargs = {
			'password': {
				'write_only': True,
				'style': {
					'input_type': 'password'
				}
			}
		}

	def create(self, validated_data):
		user = models.User.objects.create_user(
			userName = validated_data['userName'],
			fullName = validated_data['fullName'],
			email = validated_data['email'],
			password = validated_data['password'],)
		# current_site = get_current_site(request)
		# email_subject= ' Active Ac'
		# message = render_to_string('active.html', {
		# 	'user': 'user',
		# 	'domain': current_site.domain,
		# 	'uid': urlsafe_base64_encode(force_bytes(user.pk)),
		# 	'token':account_activation_token.make_token(user)
		# })
		# email = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [user.email])
		# email.send()	
		# current_site = get_current_site(request)
		# subject = "Email verification for django"
		# current_site = get_current_site(request)
		# token = account_activation_token.make_token(user)
		# activation_link = "{0}/?token{2}".format(current_site, uid, token)
		# message = "Hello {0},\n {1}".format(user.userName, activation_link)
		# email = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [user.email])
		# email.send()
		# send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])
		return user


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = models.User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    userName = serializers.CharField(
        max_length=255, min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=68, min_length=6, read_only=True)

    class Meta:
        model = models.User
        fields = ['email', 'password', 'userName', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'userName': user.userName,
            'tokens': user.tokens
        }

        return super().validate(attrs)