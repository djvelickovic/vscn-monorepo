#!/bin/sh

jq '[ .CVE_Items[] | {
      id: .cve.CVE_data_meta.ID,
      ref: [ .cve.references.reference_data[] | .url ] ,
      desc: .cve.description.description_data[0].value,
      severity: .impact.baseMetricV2.severity,
      published: .publishedDate,
      lastModified: .lastModifiedDate
    }]' "$1" > "$2"