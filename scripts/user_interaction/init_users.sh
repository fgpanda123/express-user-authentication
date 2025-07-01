#!/bin/bash

# Define the URL for the POST request
URL="http://localhost:3000/api/auth/register"

# Define the path to your JSON file containing the data
JSON_FILE="../sample_generator/registration/samples/sample-users.json"

# Read the JSON file and parse it using jq
# This example assumes a JSON array of objects, where each object
# represents a payload for one POST request.
# Adjust the jq filter (.[] or .data[] etc.) based on your JSON structure.
jq -c '.[]' "$JSON_FILE" | while read -r payload; do
  echo "Sending payload: $payload"

  # Send the POST request using curl
  # -X POST: Specifies the HTTP POST method
  # -H "Content-Type: application/json": Sets the Content-Type header
  # -d "$payload": Sends the JSON payload from the variable
  curl -X POST \
       -H "Content-Type: application/json" \
       -d "$payload" \
       "$URL"

  # Optional: Add a delay between requests to avoid overwhelming the server
  sleep 1
done