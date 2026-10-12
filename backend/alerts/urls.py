from django.urls import path
from . import views

# Read-only and scoring endpoints only. There are deliberately NO endpoints that block,
# isolate, quarantine or otherwise act on a host, user or account.
urlpatterns = [
    path("health/", views.HealthView.as_view(), name="health"),
    path("score/", views.ScoreView.as_view(), name="score"),
    path("alerts/", views.AlertListView.as_view(), name="alert-list"),
    path("alerts/<int:pk>/", views.AlertDetailView.as_view(), name="alert-detail"),
    path("summary/", views.SummaryView.as_view(), name="summary"),
]
