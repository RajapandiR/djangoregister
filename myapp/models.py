from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
# Create your models here.

class UserManager(BaseUserManager):

	def create_user(self, email, userName,fullName, password=None):
		"""Create a User """
		if not email :
			raise ValueError('User must have an Email Address')

		email = self.normalize_email(email)
		user = self.model(email=email ,userName=userName, fullName=fullName)
		user.set_password(password)
		user.save(using=self._db)
		return user

	def create_superuser(self, email, userName,fullName, password):

		user = self.create_user(email, userName,fullName, password)
		user.is_superuser = True
		user.is_staff = True
		user.save(using=self._db)
		return user

class User(AbstractBaseUser, PermissionsMixin):
	email = models.EmailField(max_length=100, unique= True)
	userName = models.CharField(max_length=100)
	fullName = models.CharField(max_length=100)
	is_verified = models.BooleanField(default = False)
	is_active = models.BooleanField(default = True)
	is_staff = models.BooleanField(default = False)

	objects = UserManager()
	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['userName', 'fullName']
	
	def get_full_name(self):
		return self.userName

	def __str__(self):
		return self.email

	def tokens(self):
		refresh = RefreshToken.for_user(self)
		return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

class Token(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)