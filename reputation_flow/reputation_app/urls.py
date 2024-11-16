from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
urlpatterns=[
    path('',views.index,name='landing'),
    path('login/',views.loginUser,name='login'),
    path('logout/',views.logoutUser,name='logout'),
    path('b/<str:company_id>/dashboard',views.dashboard,name='dashboard'),
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
    # send chat       
    path('send-chat/',views.sendChat,name='send-chat'),
    
    # instagram
    path('instagram-callback/',views.instagram_callback,name='instagram_callback'),
    # facebook
    path('facebook-callback/',views.facebook_callback,name='facebook_callback'),
    # tiktok 
    path('tiktok-callback/',views.tiktok_callback,name='tiktok_callback'),
    # youtube
    path('youtube-callback/',views.youtube_callback,name='youtube_callback'),
    # reddit
    path('reddit-callback/',views.reddit_callback,name='reddit_callback'),
    # pinterest
    path('pinterest-callback/',views.pinterest_callback,name='pinterest_callback'),
    
    # upload 
    path('upload_post/',views.uploadPost,name='upload_post'),
    # reddit flairs
    path('reddit_flairs/',views.redditFlairs,name='reddit_flairs'),

]
# Serve media files during development
# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)