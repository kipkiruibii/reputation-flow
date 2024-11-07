from django.contrib import admin
from .models import *

admin.site.register(MemberProfile)
admin.site.register(Company)
admin.site.register(CompanyProfilePicture)
admin.site.register(CompanyMember)
admin.site.register(CompanyContacts)
admin.site.register(CompanyPosts)
admin.site.register(CompanyReviews)
admin.site.register(CompanyTeam)
admin.site.register(CompanyTeamChat)
admin.site.register(CompanyTeamInviteLinks)
admin.site.register(CompanyTeamFiles)
admin.site.register(CompanyTeamAnnouncements)

# socials
admin.site.register(CompanyInstagram)
admin.site.register(CompanyFacebook)
admin.site.register(CompanyTiktok)
admin.site.register(CompanyReddit)