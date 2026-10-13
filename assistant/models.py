from django.conf import settings
from django.db import models
from django.utils import timezone

class Incident(models.Model):
    SEVERITIES = [('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')]
    STATUSES = [('New', 'New'), ('Investigating', 'Investigating'), ('Resolved', 'Resolved')]
    title = models.CharField(max_length=160)
    description = models.TextField()
    severity = models.CharField(max_length=12, choices=SEVERITIES, default='Medium')
    status = models.CharField(max_length=20, choices=STATUSES, default='New')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    ai_summary = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    @property
    def age_hours(self):
        return (timezone.now() - self.created_at).total_seconds() / 3600
