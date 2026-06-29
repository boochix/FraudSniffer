import sys
import os

# Add fraud_sniffer/ directory to sys.path so that tests can import 'fraudsniffer' package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
