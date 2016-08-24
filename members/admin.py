from django.contrib import admin
from members.models import *

admin.site.register(MemberUser)
admin.site.register(ContractCategory)
admin.site.register(ChallengeLevel)

class ContractAdmin(admin.ModelAdmin):
        readonly_fields = ('flag_prehash','flag_hash',)

admin.site.register(Contract,ContractAdmin)
admin.site.register(Capture)
admin.site.register(NewsFeed)
admin.site.register(CTFGame)
