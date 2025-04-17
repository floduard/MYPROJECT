from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from authentication.models import Profile

class Command(BaseCommand):
    help = 'Create missing profile objects for users'

    def handle(self, *args, **kwargs):
        users_without_profiles = User.objects.filter(profile__isnull=True)
        for user in users_without_profiles:
            Profile.objects.create(user=user)
            self.stdout.write(self.style.SUCCESS(f'Created profile for user: {user.username}'))
        self.stdout.write(self.style.SUCCESS('All missing profiles have been created.'))