"""
FILE: backend/users/models.py
DESCRIPTION: This file defines the core User model for the entire project.
PROJECT PART: Backend (Django Models)
INTERACTIONS: 
- Used by 'users/serializers.py' to convert user data to JSON.
- Used by 'users/views.py' for authentication and registration logic.
- Used throughout the 'restaurant' app to link orders and reviews to specific people.
"""

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import datetime
import hashlib

# ==========================================
# CUSTOM USER MODEL - ✅ ADDED ROLE SUPPORT
# ==========================================
class User(AbstractUser):
    """
    PURPOSE: Extends the default Django User to support specific roles needed for a restaurant app.
    """
    ROLE_CHOICES = [
        ('user', 'User'),         # Regular customer who orders food
        ('employee', 'Employee'), # Staff member who manages orders
        ('admin', 'Admin'),       # Manager who controls everything
    ]
    
    role = models.CharField(
        max_length=20, 
        choices=ROLE_CHOICES, 
        default='user',
        help_text="Determines what the user can see and do in the app."
    )
    
    phone = models.CharField(max_length=15, blank=True, null=True)

    def __str__(self):
        return f"{self.username} ({self.role})"

# ==========================================
# OTP MODEL - ✅ SECURE STORAGE & EXPIRY
# ==========================================
class OTP(models.Model):
    phone = models.CharField(max_length=15, unique=True)
    otp_hash = models.CharField(max_length=64) # Hashed OTP
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    last_sent_at = models.DateTimeField(auto_now=True)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"OTP for {self.phone} - Verified: {self.is_verified}"

    class Meta:
        verbose_name = "OTP Verification"
        verbose_name_plural = "OTP Verifications"
