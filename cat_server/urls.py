from django.urls import path

from cat_server.views import CATCreationKeyView, CATVerificationKeyView

app_name = "cat_server"

urlpatterns = [
    path("verification_key/", CATVerificationKeyView.as_view(), name="cat_verification_key"),
    path("creation_key/", CATCreationKeyView.as_view(), name="cat_creation_key"),
]
