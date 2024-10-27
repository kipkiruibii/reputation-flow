from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
urlpatterns=[
    path('',views.index,name='landing'),
    path('login/',views.loginUser,name='login'),
    path('logout/',views.logoutUser,name='logout'),
    path('business/id/<str:company_id>/dashboard',views.dashboard,name='dashboard'),
    path('profile/<str:company_name>/details/',views.companyProfile,name='company_profile'),
    path('update-profile/',views.updateBusinessProfile,name='update-profile'),
    # get posts
    path('fetch-posts/',views.fetchPosts,name='fetch-posts'),
    # create team
    path('create-team/',views.createTeam,name='create-team'),
    # get teams
    path('fetch-team/',views.fetchTeams,name='fetch-team'),
    # delete team
    path('delete-team/',views.deleteTeam,name='delete-team'),
    # view team
    path('view-team/',views.viewTeam,name='view-team'),
    # generate invite link team
    path('generate-invite-link/',views.generateInviteLink,name='generate-invite-link'),


    # social 
    path('instagram-redirect/',views.instagram_post_url,name='instagram_redirect'),


]
# Serve media files during development
# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)