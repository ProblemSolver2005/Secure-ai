from django.contrib import admin
from .models import Incident

@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'severity', 'status', 'source_ip', 'created_at')
    list_filter = ('severity', 'status', 'created_at')
    search_fields = ('title', 'description', 'source_ip')
