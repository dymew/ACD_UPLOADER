import sys
try:
    from django.db import models
except Exception:
    print("Exception: Django Not Found, please install it with \"pip install django\".")
    sys.exit()


# Entry
class Entry(models.Model):
    local_shasum = models.CharField(max_length=255, default="")
    acd_shasum = models.CharField(max_length=255, default="")
    path = models.CharField(max_length=255, default="")
    prev_path = models.CharField(max_length=255, default="")
    is_dir = models.BooleanField(default=False)
    last_check_date = models.BigIntegerField(default=0)

    def __str__(self):
        return self.path

    __repr__ = __str__
