#!/usr/bin/env bash

echo "this is stdout message"

>&2 echo "this is stderr message"
