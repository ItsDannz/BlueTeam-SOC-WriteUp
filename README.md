# 🛡️ SOC & Blue Team Write-ups

My personal archive of SOC investigations, Blue Team labs, and defensive security write-ups.

I use this repository to document my learning process: investigating alerts, analyzing
artifacts, correlating evidence, and explaining the reasoning behind each finding.
The focus is on reproducible investigation steps, clear reporting, and conclusions
supported by evidence.

This archive brings together write-ups from different training platforms, CTF
challenges, and independent lab exercises. It will grow as I explore new tools,
techniques, and investigation scenarios.

Write-ups can be grouped by platform or source, with a separate directory for each
investigation. This keeps the archive open to new platforms and types of exercises.

## Browsing the Archive

```text
<platform-or-source>/
    |-- <investigation-name>/
        |-- README.md
        |-- assets/
```

The case README contains the investigation. The `assets/` directory holds supporting
screenshots, diagrams, and selected evidence excerpts. Large datasets and executable
samples can be referenced by their original source and file hashes.

## Investigation Approach

1. **Understand the context:** Identify the scenario, investigation objective,
   available evidence, and relevant limitations.
3. **Examine the evidence:** Use the appropriate tools to inspect logs, network
   traffic, memory, and file artifacts.
4. **Correlate findings:** Connect users, hosts, timestamps, and indicators across
   available sources, checking time zones where needed.
5. **Assess what the evidence supports:** Separate confirmed observations from
   hypotheses, record uncertainty, and explain classification or escalation decisions.
6. **Document the outcome:** Present the timeline, supporting evidence, findings,
   relevant response recommendations, and lessons learned.

## Write-up Format

Individual write-ups use the following sections where relevant:

- **Overview:** platform or source, scenario, objectives, and investigation scope.
- **Environment:** tools, artifacts, and data sources.
- **Investigation:** steps taken, queries, filters, commands, evidence, and supporting screenshots.
- **Findings:** observed activity, affected entities, and the reconstructed timeline.
- **Indicators:** relevant IP addresses, domains, URLs, file names, and hashes.
- **Lessons learned and references:** takeaways, improvements, and supporting resources.

## Learning Notes

These write-ups document hands-on learning in training and lab environments. They
reflect my understanding at the time of writing and may be revised as I learn more
or identify a better-supported interpretation.

Corrections and alternative approaches are welcome through GitHub issues or pull
requests. Please include the reasoning or evidence behind a suggested change.
