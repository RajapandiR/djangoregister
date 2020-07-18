from django.urls import path, include
from myapp import views
from rest_framework import routers

router = routers.DefaultRouter()
router.register('user', views.UserViewSet)
# router.register('stud-profile', views.StudProfileViewSet)

urlpatterns = [
	path('users/', views.UserApiView.as_view()),
	# path('login/', views.UserLoginView.as_view()),
	path('', include(router.urls)),
]