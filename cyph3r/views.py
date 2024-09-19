from django.shortcuts import render


def index(request):
    return render(request, "cyph3r/index.html")
