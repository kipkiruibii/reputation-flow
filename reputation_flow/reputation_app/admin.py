from django.contrib import admin
from .models import *

admin.site.register(MemberProfile)
admin.site.register(Company)
admin.site.register(CompanyProfilePicture)
admin.site.register(CompanyMember)
admin.site.register(CompanyContacts)
admin.site.register(CompanyReviews)
admin.site.register(CompanyTeam)
admin.site.register(CompanyTeamChat)
admin.site.register(CompanyTeamInviteLinks)
admin.site.register(CompanyTeamFiles)
admin.site.register(CompanyTeamAnnouncements)
admin.site.register(CompanyKnowledgeBase)
admin.site.register(UploadedFiles)
admin.site.register(CompanyTeamActivity)

# PM
admin.site.register(CompanyPrivateConversation)
admin.site.register(ConversationMessages)


# socials
admin.site.register(CompanyInstagram)
admin.site.register(CompanyFacebook)
admin.site.register(CompanyTiktok)
admin.site.register(CompanyReddit)

# posts
admin.site.register(CompanyPosts)
admin.site.register(CompanyPostsComments)
admin.site.register(CompanyPostsCommentsReplies)
admin.site.register(CompanyRedditPosts)
admin.site.register(CompanyInstagramPosts)
admin.site.register(CompanyFacebookPosts)
admin.site.register(CompanyTiktokPosts)
admin.site.register(UploadedMedia)

# reddit models
admin.site.register(CompanyRedditSubs)
