#!/bin/sh

jq '[ .CVE_Items[] | {
      id: .cve.CVE_data_meta.ID,
      config: .configurations
    }]' "$1" > "$2"