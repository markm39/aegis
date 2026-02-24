#!/bin/bash
set -euo pipefail
INPUT=$(cat)
LOCATION=$(echo "$INPUT" | jq -r '.parameters.args | join(" ")')

if [ -z "$LOCATION" ]; then
  echo '{"result": "Usage: /weather <city_name_or_zip>", "artifacts": [], "messages": []}'
  exit 0
fi

if [ -z "${OPENWEATHER_API_KEY:-}" ]; then
  echo '{"result": "OPENWEATHER_API_KEY not set. Get a free key at openweathermap.org/api", "artifacts": [], "messages": []}'
  exit 0
fi

ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$LOCATION'))")
RESP=$(curl -s "https://api.openweathermap.org/data/2.5/weather?q=$ENCODED&appid=$OPENWEATHER_API_KEY&units=imperial" 2>&1)

COD=$(echo "$RESP" | jq -r '.cod' 2>/dev/null)
if [ "$COD" != "200" ]; then
  MSG=$(echo "$RESP" | jq -r '.message // "Location not found"')
  RESULT_JSON=$(echo "Error: $MSG" | jq -Rs .)
  echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
  exit 0
fi

RESULT=$(echo "$RESP" | jq -r '"## Weather for \(.name), \(.sys.country)\n\nCondition: \(.weather[0].description)\nTemp: \(.main.temp)F (feels like \(.main.feels_like)F)\nHumidity: \(.main.humidity)%\nWind: \(.wind.speed) mph\nPressure: \(.main.pressure) hPa\nVisibility: \((.visibility // 0) / 1000) km"')

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
