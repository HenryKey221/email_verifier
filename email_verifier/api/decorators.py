from functools import wraps
from django.http import JsonResponse
from .models import CreditToken

def token_required(view_func):
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        auth_header = request.headers.get("API-TOKEN")
        if not auth_header:
            return JsonResponse({"error": "API token required"}, status=401)

        token = auth_header.replace("Bearer ", "").strip()
        try:
            credit_token = CreditToken.objects.get(token=token)
        except CreditToken.DoesNotExist:
            return JsonResponse({"error": "Invalid API token"}, status=403)

        # if credit_token.balance <= 0:
        #     return JsonResponse({"error": "Insufficient credits"}, status=402)

        # Deduct 1 credit per API call
        credit_token.balance -= 1
        credit_token.save()

        return view_func(self, request, *args, **kwargs)

    return wrapper
