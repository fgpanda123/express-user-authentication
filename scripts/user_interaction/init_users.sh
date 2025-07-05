#!/bin/bash

URL="http://localhost:3000/api/auth/register"

JSON_FILE="../sample_generator/registration/samples/sample-users.json"

# Adjust the jq filter (.[] or .data[] etc.) based on your JSON structure.
jq -c '.[]' "$JSON_FILE" | while read -r payload; do
  echo "Sending payload: $payload"

  curl -X POST \
       -H "Content-Type: application/json" \
       -d "$payload" \
       "$URL"

  sleep 1
done
