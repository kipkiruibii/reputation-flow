from django.urls import path
from . import views
urlpatterns=[
    path('',views.index,name='landing'),
    path('login/',views.login,name='login'),
    path('logout/',views.logout,name='logout'),
    path('register/',views.register,name='register'),
    path('business/id/<int:company_id>/details/',views.dashboard,name='dashboard.html')
]