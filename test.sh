#!/bin/sh

req='{"UserJwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ4NTYwMDA1OTYsInVzZXJuYW1lIjoidGVzdHVzZXIifQ.oMr50cRBsyZk4DmtDVk8Xmqi6j4Ck3cuUbTcpIOnB7o","Questions":["Q1","Q2"],"Answers":["A1","A2"]}'

echo "Request:  $req"
resp=$(curl -s $* -H "Content-Type: application/json" -d $req http://localhost:8080/sign)
echo "Response: $resp"
echo

req=$(echo $resp | jq -c '.Username="testuser"')

echo "Request:  $req"
resp=$(curl -s $* -H "Content-Type: application/json" -d $req http://localhost:8080/verify)
echo "Response: $resp"
