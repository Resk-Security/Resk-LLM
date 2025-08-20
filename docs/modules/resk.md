---
title: Orchestrator (RESK)
---

## Overview

`resk_llm.RESK.RESK` orchestrates filters, detectors, managers, and integrations.

## Basic usage

```python
from resk_llm.RESK import RESK

resk = RESK()
out = resk.process_prompt("Hello")
```

## Configuration

```python
from resk_llm.RESK import RESK
from resk_llm.filters.resk_heuristic_filter import RESK_HeuristicFilter

resk = RESK(
    filters=[RESK_HeuristicFilter()],
    model_info={"context_window": 2048, "model_name": "custom-llm"}
)
```

## Returned structure

The `process_prompt` result includes: `input`, `filters`, `detectors`, `managers`, `output`, `blocked`, `reason`.

