#!/usr/bin/env bash
set -euo pipefail

# --- Script Information ---
#
# Name:         benchmark.sh
# Description:  Performs a benchmark test against an R2 presigned URL generation endpoint.
#               The script can operate in two modes:
#               1. 'batch': Makes one API request to generate N presigned URLs for N files.
#               2. 'sequential': Makes N individual API requests, each generating one presigned URL.
# Author:       Chris Brewer <https://github.com/cgcb>
# Version:      1.0.5
# Last Updated: 2025-05-29
#
# Usage:        ./benchmark.sh -n <number_of_urls> -m <mode: batch|sequential> [-v]
#
# Options:
#   -n <number>:  Number of URLs to request (e.g., 10, 200). This corresponds to the
#                 number of file entries in 'batch' mode, or the number of
#                 individual API calls in 'sequential' mode.
#   -m <mode>:    Mode of operation. Must be one of:
#                 'batch'      - One API call requesting all N URLs at once (batch processing).
#                 'sequential' - N individual API calls, each requesting one URL.
#   -v:           Verbose. If set, also prints the full HTTP response body after the
#                 standard output for the batch request or each sequential request.
#
# Requirements:
#   - bash
#   - curl
#   - bc (for floating point arithmetic in sequential timing)
#   - Common Unix utilities: seq, mktemp, date, printf, IFS, rm, echo, getopts
#
# Exit Codes:
#   0: Success
#   1: Invalid usage, incorrect options, or runtime error.
#   (Specific curl errors may result in other non-zero exit codes if not caught explicitly)
#
# --- Configuration ---
ENDPOINT="YOUR_R2_PRESIGNED_URL_ENDPOINT_HERE"
TOKEN="YOUR_KNOWN_INVALID_TOKEN_HERE"
FILENAME_BASE="example"
FILENAME_EXT="jpg"
TYPE="item_image"
# --- End Configuration ---

usage() {
  echo "Usage: $0 -n <number_of_urls> -m <mode: batch|sequential> [-v]"
  echo "  -n: Number of URLs to request (e.g., 10, 200)"
  echo "  -m: Mode of operation: "
  echo "      'batch'      - One API call requesting all N URLs at once (batch processing)."
  echo "      'sequential' - N individual API calls, each requesting one URL."
  echo "  -v: Verbose. If set, also prints the full HTTP response body."
  exit 1
}

NUM_URLS=""
MODE=""
VERBOSE_OUTPUT="" # Default to empty (false)

while getopts ":n:m:v" opt; do
  case $opt in
    n) NUM_URLS="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    v) VERBOSE_OUTPUT="yes" ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
  esac
done

if [[ -z "$NUM_URLS" ]] || [[ -z "$MODE" ]]; then
  echo "Error: Both -n and -m options are required."
  usage
fi

if ! [[ "$NUM_URLS" =~ ^[0-9]+$ ]] || (( NUM_URLS < 1 )); then
  echo "Error: Number of URLs (-n) must be a positive integer."
  usage
fi

if [[ "$MODE" != "batch" ]] && [[ "$MODE" != "sequential" ]]; then
  echo "Error: Mode (-m) must be 'batch' or 'sequential'."
  usage
fi

echo "Running benchmark..."
echo "Mode: $MODE"
echo "Number of URLs to request (N): $NUM_URLS"
if [[ -n "$VERBOSE_OUTPUT" ]]; then
  echo "Verbose output: enabled (full response body will be shown)"
fi
echo "Endpoint: $ENDPOINT"
echo "------------------------------------------"

tmp_payload_file=$(mktemp)
# Temporary file to store the response body, used in both modes
tmp_response_body=$(mktemp)
# Ensure all temp files are deleted on exit
trap 'rm -f "$tmp_payload_file" "$tmp_response_body"' EXIT

if [[ "$MODE" == "batch" ]]; then
  echo "Preparing $NUM_URLS file entries for a single JSON payload (batch mode)..."
  files_json_array=()
  for i in $(seq 1 "$NUM_URLS"); do
    current_filename="${FILENAME_BASE}${i}.${FILENAME_EXT}"
    files_json_array+=("{\"filename\":\"${current_filename}\",\"type\":\"${TYPE}\"}")
  done

  printf -v full_json_payload '{"files":[%s]}' "$(IFS=,; echo "${files_json_array[*]}")"
  echo "$full_json_payload" > "$tmp_payload_file"
  
  echo "Sending 1 request with $NUM_URLS file entries (batch mode)..."
  
  # Response body is saved to tmp_response_body
  curl_output_info=$(curl -s -o "$tmp_response_body" \
    -w "HTTP_STATUS:%{http_code}, Mode: batch, N=$NUM_URLS, time_total: %{time_total}s\n" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -X POST "$ENDPOINT" \
    --data @"$tmp_payload_file")
  
  echo "$curl_output_info"

  # Extract HTTP status code
  http_status_code=$(echo "$curl_output_info" | sed -n 's/.*HTTP_STATUS:\([0-9]\{3\}\).*/\1/p')

  if [[ "$http_status_code" == "207" ]]; then
    echo "Batch mode returned HTTP 207 (Multi-Status)."
  elif [[ -n "$http_status_code" ]] && [[ "$http_status_code" -ne 200 ]]; then
    echo "ERROR: Batch mode request failed with HTTP Status: $http_status_code"
  elif [[ -z "$http_status_code" ]]; then
    echo "ERROR: Could not extract HTTP status code for batch mode."
  fi

  if [[ -n "$VERBOSE_OUTPUT" ]]; then
    echo "--- Full Response Body (Batch) ---"
    cat "$tmp_response_body"
    echo # Add a newline after cat
    echo "--- End Response Body (Batch) ---"
  fi

elif [[ "$MODE" == "sequential" ]]; then
  echo "Preparing to send $NUM_URLS sequential requests (1 file per request)..."
  
  total_time_start=$(date +%s.%N)
  
  for i in $(seq 1 "$NUM_URLS"); do
    current_filename="${FILENAME_BASE}${i}.${FILENAME_EXT}"
    single_file_json="{\"files\":[{\"filename\":\"${current_filename}\",\"type\":\"${TYPE}\"}]}"
    echo "$single_file_json" > "$tmp_payload_file"
    
    echo -ne "Sending request $i/$NUM_URLS for ${current_filename}... \r"

    # Response body is saved to tmp_response_body (overwritten for each request)
    curl_response_code=$(curl -s -o "$tmp_response_body" \
      -w "%{http_code}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $TOKEN" \
      -X POST "$ENDPOINT" \
      --data @"$tmp_payload_file")
    
    # Always print the status code for the sequential request, then clear the line if not verbose or not an error
    # This ensures the status code is seen before potentially being overwritten by the next "Sending request..."
    if [[ "$curl_response_code" -ne 200 ]] && [[ "$curl_response_code" -ne 207 ]]; then
        echo -e "\nError on request $i: HTTP $curl_response_code for ${current_filename}" # Newline if error
    else 
        echo -ne "Request $i/$NUM_URLS for ${current_filename}: HTTP $curl_response_code        \r" # Stay on same line if OK
    fi

    if [[ -n "$VERBOSE_OUTPUT" ]]; then
      if ! ([[ "$curl_response_code" -eq 200 ]] || [[ "$curl_response_code" -eq 207 ]]); then 
          echo "--- Full Response Body (Failed Sequential Request $i: ${current_filename}) ---" # Already on a new line due to error message
      else 
          # If not an error, but verbose, we need a newline before printing the body
          echo # Move to a new line before printing body for successful verbose request
          echo "--- Full Response Body (Sequential Request $i: ${current_filename}) ---"
      fi
      cat "$tmp_response_body"
      echo # Add a newline after cat
      echo "--- End Response Body (Sequential Request $i) ---"
    fi
  done
  echo # Ensure the line from echo -ne is cleared before printing summary
  
  total_time_end=$(date +%s.%N)
  total_runtime=$(echo "$total_time_end - $total_time_start" | bc -l)
  
  printf "Mode: sequential, N=%d, Total wall clock time for loop: %.3fs\n" "$NUM_URLS" "$total_runtime"
  average_time_per_request=$(echo "$total_runtime / $NUM_URLS" | bc -l)
  printf "Average time per request (sequential): %.4fs\n" "$average_time_per_request"

fi

echo "------------------------------------------"
echo "Benchmark finished."
