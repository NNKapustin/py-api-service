from celery import shared_task
from django.conf import settings
from django.core.mail import EmailMultiAlternatives


@shared_task()
def send_email_task(title, message, addressee_list, sender=settings.EMAIL_HOST_USER):
    # send email to user
    msg = EmailMultiAlternatives(title, message, sender, addressee_list)
    msg.send()
