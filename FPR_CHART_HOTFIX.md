# FPR chart hotfix

This hotfix addresses a Streamlit Cloud crash while rendering the one-versus-rest false-positive-rate (FPR) chart.

## Files in this patch
- `app.py`: passes the FPR data frame directly to Plotly and falls back to a data table if optional chart rendering fails.
- `nids_dashboard.py`: `fpr_frame()` now returns explicit `Class` and `False positive rate` columns (not a named index).
- `tests/test_dashboard.py`: verifies the FPR data schema and Plotly Express compatibility.

## Apply on Windows
1. Extract the ZIP into `D:\FUSE AI 201\Group19_NIDS_Module6_Prototype`, replacing these three files.
2. Do not delete or replace `artifacts/` or the trained `.joblib` model.
3. In Git Bash:

```bash
cd "/d/FUSE AI 201/Group19_NIDS_Module6_Prototype"
source .venv/Scripts/activate
python -m pytest -q
```

Expected: `29 passed`.

4. Commit and push:

```bash
git status -sb
git add app.py nids_dashboard.py tests/test_dashboard.py FPR_CHART_HOTFIX.md
git commit -m "Fix FPR chart data schema in Streamlit dashboard"
git push origin main
```

If `git push` is rejected, first run `git fetch origin`. Since the hotfix should already be committed and the working tree clean, then run `git pull --rebase origin main` followed by `git push origin main`. If rebase reports a conflict, stop and inspect the conflict rather than force-pushing.

Streamlit Community Cloud should redeploy from the updated `main` branch. Check its deployment logs after the rebuild.
