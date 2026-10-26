# Ghost Data Still Exists — deletion audit agent

This repository contains a deterministic Python solution for HackerRank Orchestrate's **Ghost Data Still Exists** challenge. It reads the official participant dataset from `dataset/`, reconstructs identities and relevant resource evidence at each audit cutoff, applies the supplied treatment rules, and writes the required `output.csv`.

## Requirements

- Python 3.10 or newer
- `pandas` (CSV processing)
- `pypdf` (PDF text extraction; images remain optional OCR evidence)

## Run on Windows

Open PowerShell in this project folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

The run writes `output.csv` in this folder and validates its header, row count, sorted case IDs, JSON arrays, and phase order. To process a small prefix while developing:

```powershell
python main.py --case-limit 10 --output work\preview.csv
```

To use a different participant dataset directory or output path:

```powershell
python main.py --dataset-dir path\to\dataset --output path\to\output.csv
```

## View the dashboard

After `output.csv` has been generated, run:

```powershell
python dashboard.py
```

This creates `dashboard.html` from the CSV and opens it in your default browser. The page is self-contained and works locally without sending the case data anywhere. Use the search box and status filter, then select a case to inspect its ordered steps. To regenerate without opening the browser, use `python dashboard.py --no-open`.

## Evaluation

Run the public sample comparison with:

```powershell
python code\evaluation\main.py
```

It reports status, step, field, and exact-sequence accuracy against `dataset/sample_output.csv`. Additional intent-classification checks are in `code/evaluation/additional_cases.py`. The report records measured results and known parser limitations.

## Design

- `ghost_audit/` implements intent classification, temporal identity resolution, evidence extraction, policy checks, and ordered remediation planning.
- `code/main.py` is a location-independent entry point.
- `dataset/` is the participant-facing challenge data.
- `code.zip` contains runnable code and reports; the dataset is excluded from the archive as required.

The agent is read-only. It proposes remediation steps but does not call production services or mutate evidence. No model or API calls are made, so the usage report records zero model tokens and zero model cost.


## GitHub repository note

This public source repository intentionally omits HackerRank's challenge dataset, generated case output, private agent traces, and chat logs. To run the agent, obtain the participant dataset from the challenge and place it in a local `dataset/` directory next to `main.py`; then follow the Windows setup steps above. Do not commit challenge data or personal traces.
