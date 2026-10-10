#!/usr/bin/env python3
"""
HaakAuth — Authentication & Authorization Security Tester
Usage: haakauth.py -u https://target.com -t "Bearer eyJ..." --modules jwt,idor
       haakauth.py -p burp_request.txt --all
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth_tester.main import main
if __name__ == "__main__":
    main()
