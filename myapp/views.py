from django.shortcuts import render
from django.views.generic import View
from rest_framework.views import APIView
from rest_framework import viewsets,generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework import filters
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.permissions import IsAuthenticated
from django.core.mail import EmailMessage

from rest_framework_simplejwt.tokens import RefreshToken

# from django.views.decorators.csrf import csrf_exempt
# from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# from django.contrib.sites.shortcuts import get_current_site
# from django.template.loader import render_to_string
# from django.utils.encoding import force_bytes,force_text, DjangoUnicodeDecodeError

from myapp import serializers, models, forms
from myproject import settings

# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# import six


from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse
import jwt

# class TokenGenerator(PasswordResetTokenGenerator):
#     def _make_hash_value(self, user, timestamp):
#         return (
#             six.text_type(user.pk) + six.text_type(timestamp) +
#             six.text_type(user.is_active)
#         )

# account_activation_token = TokenGenerator()


class UserApiView(APIView):
	serializer_class = serializers.UserSerializers
	def get(self, req, format=None):
		obj = models.User.objects.all()
		serializer = serializers.UserSerializers(obj, many=True)
		return Response(serializer.data)

	def post(self, request):
		serializer = self.serializer_class(data=request.data)
		if serializer.is_valid():
			serializer.save()
			message = f'Create Successfull'
			data = serializer.data
			user = models.User.objects.get(email=data['email'])
			token = RefreshToken.for_user(user).access_token
			current_site = get_current_site(request).domain
			relativeLink = reverse('email-verify')
			absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
			email_body = 'Hi '+user.userName + \
			' Use the link below to verify your email \n' + absurl
			# current_site = get_current_site(request)
			email_subject= ' Email verify'
			# message = render_to_string('active.html', {
			# 	'user': 'user',
			# 	'domain': current_site.domain,
			# 	# 'uid': urlsafe_base64_encode(force_bytes(request.data.pk)),
			# 	'token':account_activation_token.make_token(request.data)
			# })
			email = EmailMessage(email_subject,email_body, settings.EMAIL_HOST_USER, [user.email])
			email.send()	
			return Response({'message':message})
		else:
			return Response(
				serializer.errors,
				status = status.HTTP_400_BAD_REQUEST
				)

class VerifyEmail(View):
	def get(self):
		pass

class UserViewSet(viewsets.ModelViewSet):
	serializer_class = serializers.UserSerializers
	queryset = models.User.objects.all()
	authentication_classes = (TokenAuthentication,)
	# permission_classes = (permissions.UpdateOwnStud,)
	# filter_backends = (filters.SearchFilter,)
	# search_fields = ('name', 'email',)

class UserLoginView(ObtainAuthToken):
 	renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

class LoginAPIView(generics.GenericAPIView):
    serializer_class = serializers.LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ActivateView(View):
	def get(self, request, uidb64, token):
		try:
			uid=force_text(urlsafe_base64_encode(uidb64))
			user=models.User.object.get(pk=uid)
		except Exception as identifier:
			user=None
		if user is not None and generate_token.check_token(user, token):
			user.is_activate = True
			user.save()