from django.urls import path, include
from . import views
from django.conf import settings
from django.conf.urls.static import static
urlpatterns=[
    path('',views.index,name='landing'),
    path('login/',views.loginUser,name='login'),
    path('logout/',views.logoutUser,name='logout'),
    path('b/<str:company_id>/dashboard',views.dashboard,name='dashboard'),
    path('profile/<str:company_name>/details/',views.companyProfile,name='company_profile'),
    path('social-proof/<str:company_name>/',views.socialProof,name='social-proof'),
    path('update-profile/',views.updateBusinessProfile,name='update-profile'),
    path('post-dispute/',views.postDispute,name='post-dispute'),
    path('chatbot/', views.chatbot_widget, name='chatbot_widget'),    # setting profile
    path('setting-profile/',views.settingProfile,name='setting-profile'),
    # get posts
    path('fetch-posts/',views.fetchPosts,name='fetch-posts'),
    # create team
    path('request-feature/',views.requestFeature,name='request-feature'),
    # create team
    path('create-team/',views.createTeam,name='create-team'),
    # get teams
    path('fetch-team/',views.fetchTeams,name='fetch-team'),
    # delete team
    path('delete-team/',views.deleteTeam,name='delete-team'),
    # view teams
    path('view-team/',views.viewTeam,name='view-team'),
    # generate invite link team
    path('generate-invite-link/',views.generateInviteLink,name='generate-invite-link'),
    # send chat       
    path('send-chat/',views.sendChat,name='send-chat'),
    # upload team file
    path('upload-team-file/',views.uploadTeamFile,name='upload-team-file'),
    # delete post
    path('delete-team-file/',views.deleteTeamFile,name='delete-team-file'),
    
    path('upload_train_doc/',views.uploadTrainDoc,name='upload_train_doc'),
    # fetch reviews
    path('get_reviews/',views.companyReviews,name='get_reviews'),
    # fetch private messages
    path('get_pms/',views.getPMs,name='get_pms'),
    # fetch private messages from conversation id
    path('get_messages/',views.getMessages,name='get_messages'),
    # reply private messages from conversation id
    path('reply_pm/',views.replyPM,name='reply_pm'),
        
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
    # subreddit info
    path('check_sub_rules/',views.subRedInfo,name='check_sub_rules'),
    # reddit update saved flairs
    path('update_flairs/',views.updateFlairs,name='update_flairs'),
    # get statsde
    path('get_post_stats/',views.getStats,name='get_post_stats'),
    # get tiktok creator info
    path('get_tiktok_creator/',views.gettiktokCreatorInfo,name='get_tiktok_creator'),
    # get post comments
    path('get_post_comments/',views.getComments,name='get_post_comments'),
    # get comment replies
    path('get_comment_replies/',views.getCommentReplies,name='get_comment_replies'),
    # get post comments
    path('post_comment/',views.postComment,name='post_comment'),
    # get like comments
    path('like_comment/',views.likeComment,name='like_comment'),
    # delete post
    path('delete_comment/',views.deletePostComment,name='delete_comment'),
    
    # ai chatbot
    path('ask-bot/',views.chatbot_widget,name='ask-bot'),
    
    
    path('paypal/ipn/', include("paypal.standard.ipn.urls")),

    path('payment-success/', views.successful_payment, name='payment-success'),
    path('payment-failed/', views.failed_payment, name='payment-failed'),
    path('paypal_notification/', views.paypal_notification, name='paypal_notification'),
    
    
    # publish unpublish reviews
    # path('publish_unpublish_review/',views.publishUnpublishReviews,name='publish_unpublish_review'),
    
]
# Serve media files during development
# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)