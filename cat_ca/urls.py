from django.urls import path

from cat_ca.views import CATCreationKeyView, CATVerificationKeyView

app_name = "cat_ca"

urlpatterns = [
    path("verification_key/", CATVerificationKeyView.as_view(), name="cat_verification_key"),
    path("creation_key/", CATCreationKeyView.as_view(), name="cat_creation_key"),
]
