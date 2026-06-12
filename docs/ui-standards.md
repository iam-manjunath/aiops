# UI Standards

This project follows a Maersk-style, enterprise UI baseline for operator workflows.

## Core Principles

- Keep interfaces operational and scan-friendly (no marketing-style layouts).
- Use consistent role-based color tokens and avoid one-off hex values in new UI work.
- Keep controls compact and predictable for repeated actions.
- Maintain accessibility basics:
  - visible keyboard focus
  - readable contrast
  - clear labels and headings

## Current Baseline

- Header/navigation uses a deep brand tone.
- Primary actions use the branded action color.
- Secondary actions are neutral and bordered.
- Surfaces use restrained borders and small radii (`<= 8px`).
- Incidents, profile, status, and chat views share the same visual rules.

## Implementation Note

The current server-rendered HTML pages (`/`, `/me`, `/ui`) now use shared tokenized styles.
Any new page should reuse these same token names and interaction patterns.
