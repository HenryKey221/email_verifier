from rest_framework import serializers
from django.contrib.auth.models import User
import re
import time
import smtplib
from .models import CreditToken
from DNS import Request
import socket
import ipaddress
import logging
import os


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class CreditTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditToken
        fields = ["token", "balance"]


class EmailValidationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def __init__(self, *args, **kwargs):
        # Call the parent class's __init__ method
        super().__init__(*args, **kwargs)

        # Load disposable email domains from file
        disposable_domain_file = os.path.join(
            os.path.dirname(__file__), "disposable_domains.txt"
        )

        # Check if the file exists
        if not os.path.exists(disposable_domain_file):
            raise FileNotFoundError(
                f"Disposable domain file not found: {disposable_domain_file}"
            )

        with open(disposable_domain_file, "r") as file:
            self.disposable_domains = set(line.strip().lower() for line in file)

    def validate_email(self, value):
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

        if not re.match(email_regex, value):
            raise serializers.ValidationError("Invalid email format.")

        domain = value.split("@")[1]

        if self.is_disposable_email(domain):
            raise serializers.ValidationError(
                "Domain is disposabled and cannot be used."
            )

        if self.is_blacklisted(domain):
            raise serializers.ValidationError(
                "Domain is blacklisted and cannot be used."
            )

        if self.is_gibberish(value):
            raise serializers.ValidationError(
                "Email appears to be randomly generated or gibberish."
            )
        # if not self.validate_mx_records(domain):
        #     raise serializers.ValidationError("Invalied MX Record")

        if self.is_catch_all(domain):
            raise serializers.ValidationError(
                "Catch-all email detected. Deliverability not guaranteed."
            )

        return value

    def is_disposable_email(self, email):
        try:
            # Extract the domain from the email
            return email in self.disposable_domains
        except Exception as e:
            print(f"Error checking disposable email for {email}: {e}")
            return False  # Return False on error

    def validate_mx_records(self, domain):
        """
        Validates the MX records of a domain to ensure they are properly configured.
        If no valid MX servers are found, it displays an error message and returns False.
        """
        try:
            # Query for MX records
            req = Request()
            result = req.req(name=domain, qtype="MX")

            if not result.answers:
                print(f"Error: No MX records found for domain: {domain}")
                return False

            valid_mx_servers = []
            for answer in result.answers:
                if answer["typename"] == "MX":
                    mx_server = str(answer["data"][1])  # Extract the MX server name
                    print(f"Found MX server: {mx_server}")
                    valid_mx_servers.append(mx_server)

            # If no valid MX server was found, display an error message
            if not valid_mx_servers:
                print(f"Error: No valid MX servers found for domain: {domain}")
                return False

            # If we have at least one valid MX server, the domain passes validation
            print(
                f"Validation passed: Found {len(valid_mx_servers)} MX server(s) for domain: {domain}"
            )
            return True

        except Exception as e:
            # Handle unexpected errors gracefully
            print(f"Error validating MX records for {domain}: {e}")
            return False

    def is_catch_all(self, domain):
        try:
            # Get MX records for the domain
            req = Request()
            result = req.req(name=domain, qtype="MX")
            if not result.answers:
                return False

            # Connect to the first MX server
            mx_record = str(result.answers[0]["data"])
            server = smtplib.SMTP(timeout=5)
            server.set_debuglevel(0)
            server.connect(mx_record)
            server.helo()
            server.mail("test@example.com")
            response_code, _ = server.rcpt(f"randomaddress@{domain}")
            server.quit()

            # If the server responds with 250, it might be a catch-all
            return response_code == 250
        except Exception as e:
            print(f"Error checking catch-all: {e}")
            return False

    def is_blacklisted(self, domain):

        # DNSBL servers to check against
        blacklist_servers = {
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "duhl.dnsbl.sorbs.net",
            "b.barracudacentral.org",
            "multi.surbl.org",
            "cbl.abuseat.org",
        }

        try:
            ip_list = socket.getaddrinfo(
                domain, None, socket.AF_INET
            )  # Get all IPv4 addresses
            ip_addresses = [addr[4][0] for addr in ip_list]
        except socket.gaierror:
            # If the domain cannot be resolved, assume it's not blacklisted
            return False
        except Exception as e:
            logging.warning(f"Unexpected error resolving domain {domain}: {e}")
            return False

        # Reverse the IP addresses for DNSBL queries
        for ip in ip_addresses:
            reversed_ip = ".".join(reversed(ip.split(".")))

            # Check if IP is in any blacklist server
            for blacklist in blacklist_servers:
                try:
                    query = f"{reversed_ip}.{blacklist}"
                    socket.gethostbyname(query)
                    return True  # If a response is received, the domain is blacklisted
                except socket.gaierror:
                    continue  # No response means the domain is not blacklisted
                except Exception as e:
                    logging.warning(f"Error querying DNSBL {blacklist}: {e}")
                    continue

        # If no blacklist server reports the domain, it's safe
        return False

    def is_gibberish(self, email):
        """
        Identifies gibberish or randomly generated emails by validating both the local part and domain.
        """
        try:
            # Split email into local part and domain
            local_part, domain = email.split("@")

            # Helper function to validate a string for gibberish
            def validate_part(part):
                vowels = "aeiou"
                consonants = "bcdfghjklmnpqrstvwxyz"

                # Allow parts with numbers, underscores, and dots
                if re.match(r"^[a-zA-Z0-9._-]+$", part) is None:
                    return True  # Contains invalid characters, likely gibberish

                # Check for a balanced mix of vowels and consonants
                vowel_count = sum(1 for char in part if char in vowels)
                consonant_count = sum(1 for char in part if char in consonants)

                # If the part is too unbalanced, it might be gibberish
                if vowel_count == 0 or consonant_count == 0:
                    return True  # All vowels or all consonants is suspicious

                # Allow more leniency in consonant-to-vowel ratio
                if consonant_count > (vowel_count * 4):
                    return True  # Too many consonants compared to vowels

                # Check for repeating patterns (e.g., "aaaaaa" or "xyzxyz")
                if re.search(r"(.)\1{3,}", part):
                    return True  # Repeated characters are suspicious

                # Check for random-looking patterns (e.g., "xyz123abc")
                if len(part) > 12 and re.search(r"[a-z]{6,}[0-9]{3,}", part):
                    return True  # Long strings with mixed letters/numbers can be random

                # If none of the conditions are met, it's not gibberish
                return False

            # Apply validation to both local part and domain
            if validate_part(local_part) or validate_part(domain):
                return True  # Either the local part or domain is gibberish

            # If both parts pass validation, it's not gibberish
            return False

        except Exception as e:
            print(f"Error validating email: {e}")
            return True  # Return True (gibberish) on error
