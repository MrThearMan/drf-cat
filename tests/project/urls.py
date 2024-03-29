from django.urls import include, path

from tests.example.views import ExampleView

urlpatterns = [
    path("cat/", include("cat_ca.urls")),
    path("example/", ExampleView.as_view(), name="example"),
]
