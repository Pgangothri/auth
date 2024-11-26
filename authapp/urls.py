# auth/urls.py
from django.urls import path
from .views import signin, signup, signout, home, active  # Import the 'active' view

app_name = 'authapp'

urlpatterns = [
    path('home/', home, name='home'),
    path('signin/', signin, name='signin'),
    path('signup/', signup, name='signup'),
    path('signout/', signout, name='signout'),
    path('active/<str:uid64>/<str:token>/', active, name='active'),  # Include the 'active' view in urlpatterns
]
