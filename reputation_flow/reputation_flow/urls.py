from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('hez_admin/', admin.site.urls),
    path('', include('reputation_app.urls'))
]