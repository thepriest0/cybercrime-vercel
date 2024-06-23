#!/bin/bash
flask db upgrade  # Apply database migrations
gunicorn -w 4 -b 0.0.0.0:8000 app:app  # Start the Gunicorn server
