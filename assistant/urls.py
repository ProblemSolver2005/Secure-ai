from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('assistant/', views.ai_assistant, name='ai_assistant'),
    path('incidents/', views.incident_list, name='incident_list'),
    path('incidents/new/', views.incident_create, name='incident_create'),
    path('incidents/<int:pk>/', views.incident_detail, name='incident_detail'),
    path('incidents/<int:pk>/update/', views.incident_update, name='incident_update'),
    path('logs/analyze/', views.analyze_logs, name='analyze_logs'),
]
