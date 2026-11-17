#!/usr/bin/env python3
"""
ZeroLeak CLI runner
"""
import sys
import os

# Ensure package root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from zeroleak import main

if __name__ == "__main__":
    main()
