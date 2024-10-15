from django.urls import path
from . import views
urlpatterns=[
    path('',views.index,name='landing'),
    path('login/',views.loginUser,name='login'),
    path('logout/',views.logoutUser,name='logout'),
    path('business/id/<str:company_id>/details/',views.dashboard,name='dashboard')
]