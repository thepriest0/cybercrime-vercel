#!/bin/bash
# Apply database migrations
flask db upgrade
# Start the Flask application
exec gunicorn -b :$PORT app:app
